# contacc to-do list

## 1. Registry startup heartbeat
On server startup, if `registry_handle` is configured in `node_config.json`, automatically sign and push the current `node_address` to the registry using the in-memory decrypted private key. This makes the registry self-maintaining — move servers, restart, registry updates itself. `tools/register_node.py` becomes admin/recovery only.

## 2. Username ownership and identity portability
The encrypted private key in `node_config.json` IS the contacc identity — whoever holds it owns the registry handle. Two things needed:
- `docker-setup.sh` restore-from-backup path already skips `init_node.py` (correct), but should also run registry `--update` instead of `--register` on first boot after restore.
- `tools/export_identity.py`: package just the key material (encrypted key + argon2 salt/params) separately from the database and assets. Enables seeding a fresh instance with an existing identity without a full backup restore.

## 3. Registry profile fields
Decide what user information belongs in the registry beyond the current `{server_url, client_url, public_key, ttl}`. Full name is the obvious addition — a display name independent of OAuth, chosen by the user, so contacts can show a human name without hitting the server. Possibly nothing else; the registry is a directory, not a social profile. Needs a decision before the schema gets used widely.

## 4. "Add contact by handle" UI
Wire `registry/client.py` into the client UI: type a handle, look it up in the registry, get back a server URL, add it as a contact. This is the primary user-facing payoff of the registry.

## 5. Docker — end-to-end test on a fresh cloud VM
The Docker packaging (`Dockerfile`, `docker-compose.yml`, `deploy/docker-setup.sh`) is built and smoke-tested locally. Remaining: run `docker-setup.sh` on a fresh VM to validate the full flow including Caddy TLS, and document the Google OAuth Console setup steps (redirect URI, authorized origins).

## 6. Portable bundle / backup runbook
The `data/` directory layout in Docker is the foundation for portable backups. Needs a documented backup/restore runbook and possibly a `tools/backup.sh`. The restore path (`docker compose up` with existing `data/`) already works; just needs documentation and testing.

## 7. User profile: display name and photo
Each server needs a user profile (display name, profile photo). The profile should be public — no auth required — so the registry and prospective contacts can show it during handle lookup and "add contact" flows.

Key pieces:
- **Server**: store display name (in DB or node_config) and profile photo (encrypted in file store, decrypted and served via public `GET /profile` + `GET /profile/photo` endpoints). Add profile settings to client UI (set name, upload photo).
- **Registry**: add `display_name` and `photo_url` columns to its DB; accept them in the heartbeat/update payload; return them in `GET /lookup/{handle}`.
- **Registry web UI**: show display name + photo thumbnail when a handle resolves, so users can confirm identity before adding a contact.
- **Client "add contact"**: show the profile card (photo + display name) after registry lookup, before confirming the add.

## 8. Plaintext metadata in node_config.json
`node_config.json` stores `sso_owner_identity` (e.g. `"google:cass.everitt@gmail.com"`), `node_address`, and `registry_handle` in plaintext — readable by anyone with filesystem access, no passphrase required. The email is only used to verify incoming SSO tokens. Future hardening: consider encrypting or omitting it from the config (look it up from the encrypted DB at unlock time instead). The handle and node_address are less sensitive but still worth considering.
