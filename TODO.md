# contacc to-do list

## 2. Username ownership and identity portability — premise overtaken by escrow design
This item predates the identity/node-key separation work (roadmap items 0a–0c):
the registry handle is now owned by the **identity key** (a distinct Ed25519 key,
generated at setup, never stored on the node, escrowed at the registry encrypted
under the owner passphrase and recoverable via Google auth + passphrase). The
node's `node_config.json` key is just the operational signing key for that
deployment — losing it means re-registering a node, not losing the handle.
Remaining loose end: `tools/register_node.py --update` exists for re-registering
an existing identity against a new node, but nothing yet automates choosing
`--update` vs `--register` in the docker-setup.sh restore-from-backup path.

## 5. Docker — end-to-end test on a fresh cloud VM
The Docker packaging (`Dockerfile`, `docker-compose.yml`, `deploy/docker-setup.sh`) is built and smoke-tested locally. Remaining: run `docker-setup.sh` on a fresh VM to validate the full flow including Caddy TLS, and document the Google OAuth Console setup steps (redirect URI, authorized origins).

## 9. Cross-node post edits not picked up on reload
When a post is edited on its owning node, a different node that already fetched/cached
that post does not see the change on reload (reactions and other property changes have
the same problem). Expectation: presentation should tell the client a cached post is
"visible," and the client should then check with the owner whether it's been superseded
or has property changes (e.g. reactions) — i.e. some kind of revalidation/etag/version
mechanism for cross-node post caching is missing. Needs investigation into how posts are
fetched/cached cross-node and what a cheap "has this changed" check would look like.

## 8. Plaintext metadata in node_config.json
`node_config.json` stores `sso_owner_identity` (e.g. `"google:cass.everitt@gmail.com"`), `node_address`, and `registry_handle` in plaintext — readable by anyone with filesystem access, no passphrase required. The email is only used to verify incoming SSO tokens. Future hardening: consider encrypting or omitting it from the config (look it up from the encrypted DB at unlock time instead). The handle and node_address are less sensitive but still worth considering.

## 11. DM message requests from non-contacts

Incoming DMs from nodes not in the contact list should be accepted and stored but
surfaced in a separate "message requests" bucket rather than the main DM inbox.
This prevents unsolicited messages from cluttering the primary view while still
ensuring they are not silently dropped.

## 10. DM panel: initiate DM to a single person

The DM panel currently only supports creating group threads. It should also support
initiating a direct message to a single contact without having to go through the group
creation flow — e.g. a "Message" button on a contact's profile or a single-contact
shortcut in the new-thread dialog.

---

## Done (removed from active list)

- **#1 Registry startup heartbeat**: implemented — node signs and pushes to registry on startup and hourly.
- **#3 Registry profile fields**: decided — full name is stored in the profile table at setup, picked up by heartbeat, and searchable in the registry. No further fields planned; the registry remains a directory, not a social profile.
- **#4 "Add contact by handle" UI**: implemented — `/api/contacts/lookup` and `/api/contacts/search` wire to registry; handle search in the Add Contact dialog.
- **#6 Portable bundle / backup runbook**: superseded by a richer mechanism than the raw-`data/`-directory copy this item originally described — the web UI's Backup button produces a zip (server assets + DB export + `client_config.json`), and the setup wizard's "Restore Backup" tab re-creates a node from that zip plus the owner's passphrase and a setup token (`POST /setup/restore`). Documented in README "Backup and restore".
- **#7 User profile: display name and photo**: implemented — `/profile` and `/profile/photo` endpoints; display name and photo shown in feed, registry, and add-contact flow.
