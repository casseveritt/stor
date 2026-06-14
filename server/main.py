import base64
import logging
import os
import secrets
import sys
import time
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .config import NodeConfig
from .crypto import derive_master_key, derive_subkeys, decrypt_bytes, encrypt_bytes
from .db import open_db, init_schema, WrongPassphraseError
from . import node as node_module
from . import auth as auth_module
from . import feed as feed_module
from . import assets as assets_module
from . import auth_routes as auth_routes_module
from . import sso as sso_module
from . import write as write_module
from . import admin as admin_module
from . import posts as posts_module
from . import setup as setup_module
from . import profile as profile_module
from . import contacts as contacts_module
from . import reactions as reactions_module
from . import debug as debug_module
from . import dm as dm_module

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("contacc")


def _registry_heartbeat(
    private_key: Ed25519PrivateKey,
    node_address: str,
    handle: str,
    registry_url: str,
    node_id: str = "",
    display_name: str | None = None,
    web_address: str | None = None,
    delegation_cert: dict | None = None,
    google_identity: str | None = None,
) -> bool:
    """Sign and push an update to the registry. Returns True on success."""
    try:
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        timestamp = int(time.time())
        msg = f"contacc:update:{node_id or handle}:{node_address}:{timestamp}"
        signature = base64.b64encode(private_key.sign(msg.encode())).decode()
        payload = {"server_url": node_address, "ttl": 14400,
                   "timestamp": timestamp, "signature": signature}
        if display_name:
            payload["display_name"] = display_name
        if web_address:
            payload["web_url"] = web_address
        if delegation_cert:
            payload["delegation_cert"] = delegation_cert
        if google_identity:
            payload["google_identity"] = google_identity
        r = httpx.put(f"{registry_url.rstrip('/')}/update/{handle}", json=payload, timeout=10.0)
        if r.status_code in (404, 410):
            # Not registered, or previous entry was superseded — register fresh
            pub_b64 = base64.b64encode(pub_bytes).decode()
            reg_msg = f"contacc:register:{handle}:{node_address}:{timestamp}"
            reg_sig = base64.b64encode(private_key.sign(reg_msg.encode())).decode()
            reg_payload = {**payload, "public_key": pub_b64, "signature": reg_sig}
            r = httpx.post(f"{registry_url.rstrip('/')}/register/{handle}", json=reg_payload, timeout=10.0)
        if r.is_success:
            log.info("Registry heartbeat OK: %s → %s", handle, node_address)
            return True
        log.warning("Registry heartbeat failed %s: %s", r.status_code, r.text)
        return False
    except Exception as e:
        log.warning("Registry heartbeat error: %s", e)
        return False


def _trim_idle_memory(db_con) -> None:
    """Release SQLite page cache and unused malloc'd pages back to the OS."""
    try:
        db_con.execute("PRAGMA shrink_memory")
        db_con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception:
        pass
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except Exception:
        pass


def _initialize(app: FastAPI, config_path: Path, passphrase: str) -> None:
    """Load keys, open DB, and populate app.state. Raises WrongPassphraseError on bad passphrase."""
    config = NodeConfig.load(config_path)

    salt = bytes.fromhex(config.argon2_salt)
    log.info("Deriving keys...")
    master_key = derive_master_key(
        passphrase, salt,
        config.argon2_time_cost,
        config.argon2_memory_cost,
        config.argon2_parallelism,
    )
    db_key, file_key = derive_subkeys(master_key)

    encrypted_privkey = base64.b64decode(config.encrypted_private_key)
    try:
        privkey_bytes = decrypt_bytes(encrypted_privkey, master_key)
    except InvalidTag:
        raise WrongPassphraseError("Wrong passphrase: private key decryption failed")
    private_key = Ed25519PrivateKey.from_private_bytes(privkey_bytes)

    # Migration: generate permanent identity if missing, and ensure owner_id/node_id are separate
    if not config.user_id and not config.owner_id:
        import uuid as _uuid
        import json as _json
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK
        from cryptography.hazmat.primitives.serialization import (
            Encoding as _E, PrivateFormat as _PF, NoEncryption as _NE, PublicFormat as _PuF,
        )
        from .identity import make_delegation_cert as _mkdel
        new_id_key = _EK.generate()
        new_owner_id = str(_uuid.uuid4())
        new_node_id = str(_uuid.uuid4())
        id_pub_bytes = new_id_key.public_key().public_bytes(_E.Raw, _PuF.Raw)
        node_pub_b64 = base64.b64encode(
            private_key.public_key().public_bytes(_E.Raw, _PuF.Raw)
        ).decode()
        delegation_cert = _mkdel(new_id_key, new_owner_id, node_pub_b64, node_id=new_node_id)
        config_data = _json.loads(config_path.read_text())
        config_data["owner_id"] = new_owner_id
        config_data["node_id"] = new_node_id
        config_data["identity_public_key"] = base64.b64encode(id_pub_bytes).decode()
        config_data["identity_delegation"] = _json.dumps(delegation_cert)
        config_data.pop("encrypted_identity_private_key", None)
        config_path.write_text(_json.dumps(config_data, indent=2))
        config = NodeConfig.load(config_path)
        log.info("Generated identity: owner_id=%s node_id=%s (identity private key NOT stored)", new_owner_id, new_node_id)
    elif config.user_id and not config.owner_id:
        # Migration: existing node has user_id but not owner_id/node_id — promote user_id to
        # owner_id and generate a fresh node_id so they are distinct UUIDs
        import uuid as _uuid, json as _json
        new_node_id = str(_uuid.uuid4())
        config_data = _json.loads(config_path.read_text())
        config_data["owner_id"] = config.user_id
        config_data["node_id"] = new_node_id
        # Update delegation cert to include node_id
        if config.identity_delegation:
            try:
                cert = _json.loads(config.identity_delegation)
                cert["owner_id"] = config.user_id
                cert["node_id"] = new_node_id
                config_data["identity_delegation"] = _json.dumps(cert)
            except Exception:
                pass
        # Re-register Tang under the new node_id (old Tang key was filed under user_id)
        if config_data.get("tang_C") and config_data.get("tang_url"):
            try:
                import httpx as _hx_m, time as _t_m, base64 as _b64_m
                from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey as _X25519_m, X25519PublicKey as _X25519P_m
                from cryptography.hazmat.primitives.serialization import Encoding as _Em, PublicFormat as _PFm
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDFm
                from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256m
                from .crypto import ARGON2_TIME_COST as _TCm, ARGON2_MEMORY_COST as _MCm, ARGON2_PARALLELISM as _PARm
                reg_url = config_data["tang_url"].rstrip("/")
                node_pub_b64_m = base64.b64encode(
                    private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                ).decode()
                ts_m = int(_t_m.time())
                reg_msg_m = f"contacc:tang:register:{new_node_id}:{ts_m}"
                reg_sig_m = _b64_m.b64encode(private_key.sign(reg_msg_m.encode())).decode()
                r_tang_m = _hx_m.post(f"{reg_url}/tang/register", json={
                    "node_id": new_node_id, "identity_public_key": node_pub_b64_m,
                    "timestamp": ts_m, "signature": reg_sig_m,
                }, timeout=10)
                if r_tang_m.is_success:
                    T_pub_m = _X25519P_m.from_public_bytes(_b64_m.b64decode(r_tang_m.json()["T_pub"]))
                    c_priv_m = _X25519_m.generate()
                    S_bytes_m = c_priv_m.exchange(T_pub_m)
                    K_m = _HKDFm(_SHA256m(), 32, None, b"contacc-tang-unlock").derive(S_bytes_m)
                    from .crypto import encrypt_bytes as _enc_m
                    config_data["tang_C"] = _b64_m.b64encode(c_priv_m.public_key().public_bytes(_Em.Raw, _PFm.Raw)).decode()
                    config_data["tang_E"] = _b64_m.b64encode(_enc_m(passphrase.encode(), K_m)).decode()
                    log.info("Tang re-registered under new node_id=%s", new_node_id)
            except Exception as _te_m:
                log.warning("Could not re-register Tang during migration: %s", _te_m)
        config_path.write_text(_json.dumps(config_data, indent=2))
        config = NodeConfig.load(config_path)
        log.info("Migrated identity: owner_id=%s node_id=%s (was user_id, fresh node_id generated)", config.user_id, new_node_id)

    # Ensure delegation cert is valid; re-create from encrypted_identity_private_key if needed.
    # encrypted_identity_private_key is kept in the config permanently so bundle restores
    # can always self-heal without user intervention.
    import json as _json2
    _raw_config = _json2.loads(config_path.read_text())
    _has_id_key = "encrypted_identity_private_key" in _raw_config
    _cert_valid = False
    if _has_id_key or not _raw_config.get("identity_delegation"):
        pass  # need to (re-)create cert
    else:
        try:
            from .identity import verify_delegation_cert as _vdc2
            _node_pub_b64_chk = base64.b64encode(
                private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode()
            _cert_valid = _vdc2(_json2.loads(_raw_config["identity_delegation"]), _node_pub_b64_chk)
        except Exception:
            pass
    if _has_id_key or not _cert_valid:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _EK2
            from cryptography.hazmat.primitives.serialization import (
                Encoding as _E2, PrivateFormat as _PF2, NoEncryption as _NE2, PublicFormat as _PuF2,
            )
            from .crypto import decrypt_bytes as _dec2
            from .identity import make_delegation_cert as _mkdel2
            id_priv = _dec2(base64.b64decode(_raw_config["encrypted_identity_private_key"]), master_key)
            id_key = _EK2.from_private_bytes(id_priv)
            node_pub_b64 = base64.b64encode(
                private_key.public_key().public_bytes(_E2.Raw, _PuF2.Raw)
            ).decode()
            delegation_cert = _mkdel2(id_key, config.owner_id or config.user_id, node_pub_b64)
            _raw_config["identity_delegation"] = _json2.dumps(delegation_cert)
            # Keep encrypted_identity_private_key — bundle restores need it to self-heal.
            config_path.write_text(_json2.dumps(_raw_config, indent=2))
            config = NodeConfig.load(config_path)
            if _has_id_key and not _cert_valid:
                log.info("Delegation cert was invalid; re-created from stored identity key.")
            elif _has_id_key:
                # First-time creation — auto-upload escrow with default passphrase so recovery works.
                try:
                    from .identity import identity_key_to_hex as _id2hex
                    from .crypto import (derive_master_key as _dmk2, encrypt_bytes as _enc2,
                                         ARGON2_TIME_COST as _TC, ARGON2_MEMORY_COST as _MC, ARGON2_PARALLELISM as _PA)
                    _reg_url = (_raw_config.get("registry_url") or _raw_config.get("identity_proxy_url") or "").rstrip("/")
                    if _reg_url and (config.owner_id or config.user_id):
                        _rec_salt = os.urandom(16)
                        _rec_key = _dmk2("foobar", _rec_salt)
                        _enc_id = _enc2(id_priv, _rec_key)
                        _ts = int(time.time())
                        _escrow_sig = base64.b64encode(id_key.sign(
                            f"contacc:escrow:{config.owner_id or config.user_id}:{_ts}".encode()
                        )).decode()
                        _escrow_body = {
                            "encrypted_identity_key": base64.b64encode(_enc_id).decode(),
                            "argon2_salt": _rec_salt.hex(),
                            "argon2_time_cost": _TC, "argon2_memory_cost": _MC, "argon2_parallelism": _PA,
                            "signature": _escrow_sig, "timestamp": _ts,
                        }
                        httpx.put(f"{_reg_url}/identity-key/{config.owner_id or config.user_id}", json=_escrow_body, timeout=10)
                        log.warning("Identity key migrated. Recovery passphrase is currently 'foobar'. "
                                    "Change it in settings → Identity Security.")
                except Exception as _e2:
                    log.warning("Could not auto-upload identity escrow: %s", _e2)
        except Exception as _e:
            if not _cert_valid:
                log.error("Delegation cert is invalid and could not be re-created: %s", _e)

    # Migration: fix stale user_id in delegation cert and remove duplicate top-level user_id.
    # The cert's user_id must equal owner_id (it can diverge after multi-step migrations).
    # The top-level user_id is a legacy alias for owner_id — remove it to reduce confusion.
    import json as _json_clean
    _raw_clean = _json_clean.loads(config_path.read_text())
    _changed_clean = False
    if config.identity_delegation:
        try:
            _cert_clean = _json_clean.loads(config.identity_delegation)
            _cert_owner = _cert_clean.get("owner_id") or ""
            if _cert_owner and _cert_clean.get("user_id") != _cert_owner:
                _cert_clean["user_id"] = _cert_owner
                _raw_clean["identity_delegation"] = _json_clean.dumps(_cert_clean)
                _changed_clean = True
                log.info("Fixed stale user_id in delegation cert (was %s, now matches owner_id %s)",
                         _cert_clean.get("user_id"), _cert_owner)
        except Exception as _ce:
            log.warning("Could not fix delegation cert user_id: %s", _ce)
    if "user_id" in _raw_clean and _raw_clean.get("user_id") == _raw_clean.get("owner_id"):
        del _raw_clean["user_id"]
        _changed_clean = True
    if _changed_clean:
        config_path.write_text(_json_clean.dumps(_raw_clean, indent=2))
        config = NodeConfig.load(config_path)

    store_path = Path(config.store_path)
    db_con = open_db(str(store_path / "db"), db_key)
    init_schema(db_con)

    # Migrate reply notification nids to new scheme: sha256(reply:{reply_post_id}:{own_node_id})
    # Old scheme was sha256(reply:{parent_post_id}:{reply_post_id}), which produced a different
    # nid for each ancestor post on the same node, causing duplicate notifications.
    import hashlib as _hl_nr
    _own_nid_nr = config.node_id or ""
    if _own_nid_nr:
        _reply_rows = db_con.execute(
            "SELECT id, post_id FROM mention_notifications WHERE notif_type='reply' AND post_id != '' AND post_id IS NOT NULL"
        ).fetchall()
        _nr_changed = False
        for _old_nid, _reply_post_id in _reply_rows:
            _new_nid = _hl_nr.sha256(f"reply:{_reply_post_id}:{_own_nid_nr}".encode()).hexdigest()[:36]
            if _old_nid != _new_nid:
                if db_con.execute("SELECT 1 FROM mention_notifications WHERE id = ?", (_new_nid,)).fetchone():
                    db_con.execute("DELETE FROM mention_notifications WHERE id = ?", (_old_nid,))
                else:
                    db_con.execute("UPDATE mention_notifications SET id = ? WHERE id = ?", (_new_nid, _old_nid))
                _nr_changed = True
        if _nr_changed:
            db_con.commit()

    node_address = os.environ.get("CONTACC_NODE_ADDRESS") or config.node_address

    app.state.db = db_con
    app.state.file_key = file_key
    app.state.store_path = store_path
    app.state.config_path = config_path
    app.state.node_address = node_address
    app.state.watermark_enabled = config.watermark_enabled
    app.state.owner_identity = config.sso_owner_identity
    app.state.identity_proxy_url = config.identity_proxy_url
    app.state.sso_config = {
        "google_client_id": config.sso_google_client_id,
        "google_client_secret": config.sso_google_client_secret,
    }
    app.state.sso_exchange_google = sso_module.exchange_google_code
    app.state.user_id = config.owner_id or config.user_id or ""
    app.state.node_id = config.node_id or ""

    node_module.setup(node_address, private_key, config.watermark_enabled, config.registry_handle,
                      user_id=config.owner_id or config.user_id,
                      owner_id=config.owner_id or config.user_id,
                      node_id=config.node_id or "")
    auth_module.setup(private_key)

    app.state.private_key = private_key
    app.state.internal_token = config.internal_token

    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF2
    from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256_2
    app.state.client_cache_key = base64.b64encode(
        _HKDF2(_SHA256_2(), 32, None, b"contacc-client-cache-key").derive(master_key)
    ).decode()

    # Load or generate X25519 DH key for DM thread key derivation
    import json as _json_dh
    _config_data_dh = _json_dh.loads(config_path.read_text())
    from .crypto import generate_dh_key, load_dh_key, dh_public_key_b64 as _dh_pub_b64
    from cryptography.hazmat.primitives.serialization import (
        Encoding as _Edh, PrivateFormat as _PFdh, NoEncryption as _NEdh,
    )
    if config.encrypted_dh_private_key:
        dh_priv = load_dh_key(config.encrypted_dh_private_key, master_key)
    else:
        dh_priv, _ = generate_dh_key()
        dh_raw = dh_priv.private_bytes(_Edh.Raw, _PFdh.Raw, _NEdh())
        _config_data_dh["encrypted_dh_private_key"] = base64.b64encode(
            encrypt_bytes(dh_raw, master_key)
        ).decode()
        config_path.write_text(_json_dh.dumps(_config_data_dh, indent=2))
        log.info("Generated DH key for DM encryption")
    app.state.dh_private_key = dh_priv
    app.state.dh_public_key = _dh_pub_b64(dh_priv)
    node_module.set_dh_public_key(app.state.dh_public_key)

    app.state.master_key = master_key
    app.state.initialized = True
    log.info("Node %s ready.", node_address)

    # Notify provider of ownership so the invite button works (idempotent on restart)
    setup_module._notify_provider_claim(app, config, private_key)

    if config.registry_handle and node_address:
        registry_url = config.registry_url or config.identity_proxy_url or ""
        if registry_url:
            import threading

            HEARTBEAT_INTERVAL = 3600  # re-register every hour; TTL is 4 hours

            def _make_trigger(pk, addr, hdl, reg_url, nid, db_con, web_addr, cfg_path):
                def trigger():
                    row = db_con.execute(
                        "SELECT display_name FROM profile WHERE id = 1"
                    ).fetchone()
                    dn = row[0] if row else None
                    import json as _j
                    try:
                        _cfg = NodeConfig.load(cfg_path)
                        _dcert = _j.loads(_cfg.identity_delegation) if _cfg.identity_delegation else None
                        _gid = _cfg.sso_owner_identity
                        _hdl = _cfg.registry_handle or hdl
                    except Exception:
                        _dcert = None
                        _gid = None
                        _hdl = hdl
                    return _registry_heartbeat(pk, addr, _hdl, reg_url, nid, dn, web_addr, _dcert, _gid)
                return trigger

            def _heartbeat_loop(trigger):
                import time as _time
                RETRY_INTERVAL = 60  # retry after 1 minute on failure (e.g. Caddy TLS not yet ready)
                while True:
                    ok = trigger()
                    _retry_undelivered_dms(app)
                    _time.sleep(HEARTBEAT_INTERVAL if ok else RETRY_INTERVAL)
                    _trim_idle_memory(db_con)

            trigger_fn = _make_trigger(private_key, node_address, config.registry_handle, registry_url, config.node_id or "", db_con, app.state.web_address, config_path)
            app.state.trigger_heartbeat = trigger_fn
            threading.Thread(target=_heartbeat_loop, args=(trigger_fn,), daemon=True).start()


def _retry_undelivered_dms(app) -> None:
    """Retry pushing undelivered outgoing DMs. Runs in heartbeat thread."""
    try:
        from .crypto import dh_public_key_b64 as _dhpub, derive_thread_key, encrypt_dm
        from .auth import sign_federated_request
        import json as _j
        db = app.state.db
        cutoff = app.state.db.execute("SELECT (strftime('%s','now') * 1000000000 - 7*86400*1000000000)").fetchone()[0]
        rows = db.execute("""
            SELECT m.id, m.thread_id, m.body_enc, t.peer_url, t.peer_node_id
            FROM dm_messages m JOIN dm_threads t ON m.thread_id = t.thread_id
            WHERE m.direction = 'out' AND m.delivered_at IS NULL AND m.created_at > ?
            LIMIT 20
        """, (cutoff,)).fetchall()
        if not rows:
            return
        from .db import now_ns
        for msg_id, thread_id, body_enc, peer_url, peer_node_id in rows:
            push = {
                "id": msg_id, "thread_id": thread_id,
                "sender_node_id": app.state.node_id,
                "sender_url": app.state.node_address,
                "sender_dh_pub": app.state.dh_public_key,
                "body_enc": body_enc,
                "created_at": db.execute("SELECT created_at FROM dm_messages WHERE id=?", (msg_id,)).fetchone()[0],
            }
            push_bytes = _j.dumps(push).encode()
            headers = sign_federated_request(app.state.private_key, "POST", "/dm/receive", push_bytes)
            headers["Content-Type"] = "application/json"
            try:
                r = httpx.post(peer_url.rstrip("/") + "/dm/receive",
                               content=push_bytes, headers=headers, timeout=8)
                if r.is_success:
                    db.execute("UPDATE dm_messages SET delivered_at=? WHERE id=?", (now_ns(), msg_id))
                    db.commit()
            except Exception:
                pass
    except Exception as e:
        log.debug("DM retry error: %s", e)


def create_app(config_path: str | Path, passphrase: str = "") -> FastAPI:
    config_path = Path(config_path)

    app = FastAPI(title="contacc node")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.initialized = False
    app.state.config_path = config_path
    app.state.node_address = os.environ.get("CONTACC_NODE_ADDRESS", "")
    app.state.web_address = os.environ.get("CONTACC_WEB_ADDRESS", "")
    app.state.tang_nonces = {}  # nonce -> expiry timestamp; supports multiple outstanding attempts

    if not config_path.exists():
        setup_module.ensure_setup_token(app)

    def _do_initialize(passphrase: str) -> None:
        _initialize(app, config_path, passphrase)

    app.state.do_initialize = _do_initialize

    # Setup routes are always accessible
    app.include_router(setup_module.router)

    # Normal routes — blocked by middleware until initialized
    app.include_router(node_module.router)
    app.include_router(feed_module.router)
    app.include_router(assets_module.router)
    app.include_router(auth_routes_module.router)
    app.include_router(write_module.router)
    app.include_router(admin_module.router)
    app.include_router(posts_module.router)
    app.include_router(profile_module.router)
    app.include_router(contacts_module.router)
    app.include_router(reactions_module.router)
    app.include_router(debug_module.router)
    app.include_router(dm_module.router)

    @app.post("/notifications/mention", status_code=204)
    async def receive_mention(request: Request):
        """Receive a mention notification from another node."""
        from .auth import verify_federated_signature
        await verify_federated_signature(request)
        if not getattr(request.state, 'sig_verified', False):
            return JSONResponse({"detail": "Valid signature required"}, status_code=401)
        try:
            body = await request.json()
            post_id = body.get("post_id", "")
            author_node_id = body.get("author_node_id") or body.get("author_server", "")
            author_handle = body.get("author_handle", "")
            notif_type = body.get("notif_type", "mention")
            post_node_id = body.get("post_node_id", "") or author_node_id
            if not post_id or not author_node_id:
                return JSONResponse({"detail": "missing fields"}, status_code=400)
            db = app.state.db
            notif_id = str(__import__("uuid").uuid4())
            db.execute(
                "INSERT OR IGNORE INTO mention_notifications "
                "(id, post_id, post_node_id, author_node_id, author_handle, received_at, notif_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (notif_id, post_id, post_node_id, author_node_id, author_handle, int(time.time_ns()), notif_type)
            )
            db.commit()
        except Exception:
            pass

    @app.get("/api/notifications/mentions")
    def get_mention_notifications(request: Request):
        """Return recent mention notifications for the owner."""
        db = app.state.db
        rows = db.execute(
            "SELECT id, post_id, author_node_id, author_handle, received_at, seen, notif_type, actor_name, emoji, post_node_id "
            "FROM mention_notifications ORDER BY received_at DESC LIMIT 50"
        ).fetchall()
        return {"notifications": [
            {"id": r[0], "post_id": r[1], "author_node_id": r[2],
             "author_handle": r[3], "received_at": r[4], "seen": bool(r[5]),
             "notif_type": r[6] or "mention", "actor_name": r[7], "emoji": r[8],
             "post_node_id": r[9] or ""}
            for r in rows
        ]}

    @app.post("/api/notifications/mentions/mark-seen", status_code=204)
    def mark_mentions_seen(request: Request):
        db = app.state.db
        db.execute("UPDATE mention_notifications SET seen = 1 WHERE seen = 0")
        db.commit()

    @app.post("/api/notifications/mentions/{notif_id}/seen", status_code=204)
    def mark_mention_seen(notif_id: str, request: Request):
        db = app.state.db
        db.execute("UPDATE mention_notifications SET seen = 1 WHERE id = ?", (notif_id,))
        db.commit()

    @app.get("/internal/client-cache-key")
    def internal_client_cache_key(request: Request):
        """Return the AES key the co-located client (them) should use for its post cache."""
        key = getattr(app.state, "client_cache_key", None)
        if not key:
            raise HTTPException(status_code=503, detail="Not initialized")
        return {"key": key}

    @app.get("/registry-cache/{node_id}")
    def registry_cache_get(node_id: str, request: Request):
        """Return our locally-cached signed registry record for this node_id (for peer sharing)."""
        import json as _json
        db = request.app.state.db
        row = db.execute("SELECT record, cached_at FROM registry_cache WHERE node_id = ?", (node_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Not in cache")
        record = _json.loads(row[0])
        queried_at = record.get("queried_at", 0)
        if time.time() - queried_at > 8 * 3600:
            raise HTTPException(status_code=404, detail="Cache entry too stale")
        return record

    @app.post("/tang/deliver")
    async def tang_deliver(request: Request):
        """Receive Tang S value from registry; derive passphrase and unlock."""
        body = await request.json()
        nonce = body.get("nonce", "")
        S_b64 = body.get("S", "")
        now = time.time()
        # Purge expired nonces, then validate
        app.state.tang_nonces = {n: exp for n, exp in app.state.tang_nonces.items() if exp > now}
        if not nonce or nonce not in app.state.tang_nonces:
            return JSONResponse({"detail": "Invalid nonce"}, status_code=403)
        app.state.tang_nonces.pop(nonce)  # one-use
        if app.state.initialized:
            return {"status": "already initialized"}
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
            from cryptography.hazmat.primitives.hashes import SHA256 as _SHA256
            from .crypto import decrypt_bytes as _dec
            from .config import NodeConfig as _NC
            _cfg = _NC.load(config_path)
            S_bytes = base64.b64decode(S_b64 + "==")
            K = _HKDF(_SHA256(), 32, None, b"contacc-tang-unlock").derive(S_bytes)
            passphrase = _dec(base64.b64decode(_cfg.tang_E + "=="), K).decode()
            app.state.do_initialize(passphrase)
            log.info("Node unlocked via Tang (network-bound unlock)")
            return {"status": "ok"}
        except Exception as e:
            log.error("Tang delivery failed: %s", e)
            return JSONResponse({"detail": "Tang delivery failed"}, status_code=500)

    @app.on_event("startup")
    async def _tang_autounlock():
        """Schedule Tang-based auto-unlock after server is ready to accept connections."""
        if app.state.initialized or not config_path.exists():
            return
        import asyncio as _aio
        _aio.ensure_future(_tang_autounlock_task())

    async def _tang_autounlock_task():
        import asyncio as _aio, secrets as _sec, httpx as _hx
        try:
            from .config import NodeConfig as _NC
            _cfg = _NC.load(config_path)
        except Exception:
            return
        if not _cfg.tang_enabled or not _cfg.tang_C or not _cfg.tang_E:
            return
        registry_url = (_cfg.tang_url or _cfg.identity_proxy_url or "").rstrip("/")
        node_address = (os.environ.get("CONTACC_NODE_ADDRESS") or _cfg.node_address or "").rstrip("/")
        if not registry_url or not node_address:
            return
        # Try node_id first, fall back to owner_id/user_id (Tang keys may be filed under either)
        _tang_ids = list(dict.fromkeys(filter(None, [
            _cfg.node_id, _cfg.owner_id, _cfg.user_id
        ])))

        async def _attempt() -> bool:
            """Try Tang exchange for each candidate ID. Returns True if unlock was initiated."""
            for tang_node_id in _tang_ids:
                nonce = _sec.token_urlsafe(32)
                app.state.tang_nonces[nonce] = time.time() + 30
                try:
                    async with _hx.AsyncClient() as hc:
                        r = await hc.post(f"{registry_url}/tang/exchange", json={
                            "node_id": tang_node_id,
                            "C": _cfg.tang_C,
                            "nonce": nonce,
                            "callback_url": f"{node_address}/tang/deliver",
                        }, timeout=15)
                    if r.is_success:
                        return True  # unlock handled in /tang/deliver
                    if r.status_code != 404:
                        log.warning("Tang exchange attempt failed (%s), will retry", r.status_code)
                        break  # non-404 errors don't benefit from trying other IDs
                except Exception as e:
                    log.warning("Tang auto-unlock error: %s", e)
                    break
                app.state.tang_nonces.pop(nonce, None)
            return False

        # Fast retries: at 2s, 7s, 22s after startup
        for delay in (2, 5, 15):
            await _aio.sleep(delay)
            if app.state.initialized:
                return
            if await _attempt():
                return

        # Slow retries: every 60s for up to 30 minutes
        deadline = time.time() + 30 * 60
        while time.time() < deadline:
            await _aio.sleep(60)
            if app.state.initialized:
                return
            log.info("Tang slow-retry unlock attempt")
            if await _attempt():
                return

        log.warning("Tang auto-unlock gave up after 30 minutes")

    @app.on_event("startup")
    async def _announce_to_provider():
        """If uninitialized, announce this node as available to the provider."""
        if app.state.initialized:
            return
        provider_url_env = (os.environ.get("CONTACC_PROVIDER_NOTIFY_URL") or os.environ.get("CONTACC_PROVIDER_URL", "")).rstrip("/")
        node_address = (os.environ.get("CONTACC_WEB_ADDRESS") or os.environ.get("CONTACC_NODE_ADDRESS") or "").rstrip("/")
        if not provider_url_env or not node_address:
            return
        token_path = Path(app.state.config_path).parent / ".setup_token"
        if not token_path.exists():
            return
        setup_token = token_path.read_text().strip()
        if not setup_token:
            return
        import asyncio as _aio
        import httpx as _hx
        await _aio.sleep(3)
        if app.state.initialized:
            return
        try:
            async with _hx.AsyncClient() as _c:
                await _c.post(f"{provider_url_env}/nodes/startup",
                              json={"node_url": node_address, "setup_token": setup_token},
                              timeout=10)
            log.info("Announced availability to provider: %s", node_address)
        except Exception as e:
            log.warning("Could not announce to provider: %s", e)

    @app.middleware("http")
    async def init_guard(request: Request, call_next):
        path = request.url.path
        is_setup_path = path.startswith("/setup") or path == "/tang/deliver"
        is_public_path = (path == "/profile/photo" or path.startswith("/node")
                         or path == "/notifications/mention"
                         or path.startswith("/posts/") and path.endswith("/subscribe"))
        if not app.state.initialized and not is_setup_path:
            state = "locked" if config_path.exists() else "uninitialized"
            return JSONResponse({"detail": "Server not ready", "state": state}, status_code=503)
        if app.state.initialized and not is_setup_path and not is_public_path:
            internal_token = getattr(app.state, "internal_token", None)
            provided = request.headers.get("x-contacc-internal", "")
            if not internal_token or not secrets.compare_digest(provided, internal_token):
                return JSONResponse({"detail": "Unauthorized"}, status_code=403)
        return await call_next(request)

    if config_path.exists() and passphrase:
        try:
            _initialize(app, config_path, passphrase)
        except WrongPassphraseError as e:
            log.error("Wrong passphrase at startup — server will start in locked state: %s", e)

    return app


def _dev_factory() -> FastAPI:
    """Factory for uvicorn --reload mode; reads config path from env."""
    return create_app(os.environ["CONTACC_CONFIG"])


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run a contacc node")
    parser.add_argument("config", help="Path to node_config.json")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--reload", action="store_true", help="Reload on source changes (dev mode)")
    parser.add_argument("--print-token", action="store_true", help="Print an owner token to stdout before serving")
    args = parser.parse_args()

    if args.reload:
        os.environ["CONTACC_CONFIG"] = args.config
        uvicorn.run("server.main:_dev_factory", factory=True, host=args.host, port=args.port,
                    reload=True, reload_dirs=["/app/server"], proxy_headers=True, forwarded_allow_ips="*",
                    timeout_graceful_shutdown=1)
        return

    app = create_app(args.config)

    if args.print_token:
        if not app.state.initialized:
            log.error("--print-token requires the server to be initialized (Tang unlock must complete first)")
            sys.exit(1)
        token = auth_module.issue_token(ttl_seconds=86400 * 30)
        print(f"Owner token: {token}", flush=True)

    uvicorn.run(app, host=args.host, port=args.port,
                proxy_headers=True, forwarded_allow_ips="*")


if __name__ == "__main__":
    main()
