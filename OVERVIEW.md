# stor — Overview

`stor` is a content-addressable file store backed by BLAKE3 hashes and SQLite. It is designed for personal backup use: files are deduplicated by content, tracked in a lightweight database, and can be reconstructed into their original directory structure on demand.

## Core Concepts

- **Content-addressable storage**: Every file is stored by its `b3sum` (BLAKE3) hash under `files/<2-char-prefix>/<full-hash>`. Identical files are stored only once regardless of how many paths point to them.
- **SQLite index**: A database file (`db`) holds a `relpaths` table mapping `b3sum → relative path`. Multiple paths can map to the same hash, giving deduplication for free.
- **Hard links**: Files are imported via hard links rather than copies, keeping disk usage minimal as long as source and store share the same filesystem.

## Scripts

| Script | Purpose |
|---|---|
| `import2filestore.py` | Walk a directory, hash each file, and hard-link it into the store. Records the path→hash mapping in the DB. |
| `link2filestore.py` | Reconstruct a directory tree from the DB by hard-linking store files back to their recorded paths. |
| `fusestor.py` | Mount a read-only FUSE filesystem view of a backup directory. |
| `histchain.py` | Maintain an append-only manifest history of store contents. Each entry records additions/removals and a hash-chain checksum for integrity verification. |
| `rsync_bkup.py` | Sync from a remote server via rsync over SSH. Adds a random delay (up to 30 min) to spread load when run from cron. Logs output locally. |
| `orphans.py` | Find files in the store not referenced by any DB row, and move them to an `unreferenced/` directory. Also reports dangling DB rows whose files are missing. |
| `checkb3.py` | Verify that each file in the store matches its filename (i.e., its BLAKE3 hash). |
| `checksize.py` | Verify that the size recorded in the DB matches the actual file size on disk. |
| `popsize.py` | Populate missing size values in the DB for rows where `size = -1`. |
| `addexts.py` | Append file-type extensions to unreferenced hash filenames (using `file --extension`) for easier manual browsing. |
| `sizelist.py` | Walk a directory and print all files sorted by size, with a total byte count. |

## Typical Workflow

1. **Import** a directory into the store: `import2filestore.py <bkupdir> <importdir>`
2. **Sync** new content from a remote host: `rsync_bkup.py` (run via cron)
3. **Update the manifest**: `histchain.py <bkupdir> <manifesthist>` to record and verify what changed
4. **Reconstruct** files: `link2filestore.py <bkupdir> <linkdir>`
5. **Maintain** the store: run `orphans.py`, `checkb3.py`, and `checksize.py` periodically to verify integrity

## Directory Layout

```
<bkupdir>/
  db                      # SQLite database (relpaths table)
  files/
    <xx>/                 # Two-character hash prefix
      <full-b3sum-hash>   # File content, stored once
  unreferenced/           # Files moved here by orphans.py
```
