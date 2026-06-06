# contacc to-do list

## 2. Username ownership and identity portability
The encrypted private key in `node_config.json` IS the contacc identity — whoever holds it owns the registry handle. Two things needed:
- `docker-setup.sh` restore-from-backup path already skips `init_node.py` (correct), but should also run registry `--update` instead of `--register` on first boot after restore.
- `tools/export_identity.py`: package just the key material (encrypted key + argon2 salt/params) separately from the database and assets. Enables seeding a fresh instance with an existing identity without a full backup restore.

## 3. Registry profile fields
Decide what user information belongs in the registry beyond the current `{server_url, client_url, public_key, ttl}`. Full name is the obvious addition — a display name independent of OAuth, chosen by the user, so contacts can show a human name without hitting the server. Possibly nothing else; the registry is a directory, not a social profile. Needs a decision before the schema gets used widely.

## 5. Docker — end-to-end test on a fresh cloud VM
The Docker packaging (`Dockerfile`, `docker-compose.yml`, `deploy/docker-setup.sh`) is built and smoke-tested locally. Remaining: run `docker-setup.sh` on a fresh VM to validate the full flow including Caddy TLS, and document the Google OAuth Console setup steps (redirect URI, authorized origins).

## 6. Portable bundle / backup runbook
The `data/` directory layout in Docker is the foundation for portable backups. Needs a documented backup/restore runbook and possibly a `tools/backup.sh`. The restore path (`docker compose up` with existing `data/`) already works; just needs documentation and testing.

## 8. Plaintext metadata in node_config.json
`node_config.json` stores `sso_owner_identity` (e.g. `"google:cass.everitt@gmail.com"`), `node_address`, and `registry_handle` in plaintext — readable by anyone with filesystem access, no passphrase required. The email is only used to verify incoming SSO tokens. Future hardening: consider encrypting or omitting it from the config (look it up from the encrypted DB at unlock time instead). The handle and node_address are less sensitive but still worth considering.

---

## Done (removed from active list)

- **#1 Registry startup heartbeat**: implemented — node signs and pushes to registry on startup and hourly.
- **#4 "Add contact by handle" UI**: implemented — `/api/contacts/lookup` and `/api/contacts/search` wire to registry; handle search in the Add Contact dialog.
- **#7 User profile: display name and photo**: implemented — `/profile` and `/profile/photo` endpoints; display name and photo shown in feed, registry, and add-contact flow.
