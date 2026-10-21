---
name: fea
description: Forensic disk-image analysis through the FEA MCP server (sleuthkit, registry, event logs, SQLite, prefetch, LNK, ESE, EXIF, YARA, unallocated-space search). Use when asked to examine a disk image, find or recover files, build a timeline, or prove what happened on a machine.
---
# FEA workflow
1. `images_list` then `partitions(image)`; omit `part` to use the largest file system.
2. Locate: `find` (names, incl. deleted), `ls`, `timeline(start,end,path_regex)`. Inspect: `stat` (NTFS $FILE_NAME times, ADS), `read`, `extract`.
3. Parse artefacts in place: `registry_key` / `registry_plugins` (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache.hve), `evtx` (Security 4624/4625/4720/1102, System 7045/104), `prefetch`, `lnk`, `sqlite_tables`/`sqlite_query` (browser, chat, Android), `esedb_*` (SRUDB.dat, Windows.edb, WebCacheV01.dat), `exif`, `office_parts`, `file_info` (hashes, entropy, trailing data), `yara_scan`.
4. Content: `grep_file` for one file (pagefile.sys, hiberfil.sys), `grep_files` for a subtree, `grep_unallocated` for deleted data; both are jobs: `job_result(job_id, wait_s=30)` until status is done. Map unallocated hits with `blkcalc` then `block_read`.
5. Report every finding with its evidence block (image, partition, path, inode, sha1) and both UTC and local times; state limitations; never execute extracted binaries.
