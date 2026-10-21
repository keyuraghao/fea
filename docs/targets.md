# Targets and checklists

What to open, where it lives, and which FEA tool reads it. Paths are Windows 10/11 defaults unless noted.

## Images

- Raw (`.dd`, `.raw`, `.img`), split raw (`name.001`, `name.002`, ...: register the first segment), EWF/E01 (first segment). `partitions` probes each partition for a file system; omit `part` to take the largest.
- Android-x86 and similar VM images are plain ext4 and work like Linux.
- OS/2 HPFS and other file systems The Sleuth Kit does not parse: `disk_read`, `strings --local` on the image file, or carve with other tools.

## Windows

| Question | Artefact | Tool |
|---|---|---|
| Machine identity, timezone, network | `Windows/System32/config/SYSTEM` (`ControlSet001\Control\ComputerName`, `TimeZoneInformation`, `Services\Tcpip\Parameters\Interfaces`) | `registry_key` |
| OS version, install date, profiles | `config/SOFTWARE` (`Microsoft\Windows NT\CurrentVersion`, `...\ProfileList`) | `registry_key` |
| Local accounts | `config/SAM` | `registry_plugins` (`sam_users`?) / `registry_key` |
| What the user ran and searched | `Users/<u>/NTUSER.DAT` UserAssist, RunMRU, WordWheelQuery, TypedPaths, RecentDocs | `registry_plugins`, `registry_key` |
| Folders browsed, removable media | `Users/<u>/AppData/Local/Microsoft/Windows/UsrClass.dat` (ShellBags), `SYSTEM` USBSTOR/MountedDevices | `registry_plugins` |
| Program execution | `Windows/Prefetch/*.pf`, `Windows/appcompat/Programs/Amcache.hve` | `prefetch`, `registry_key` |
| Logons, log clearing, services, tasks | `Windows/System32/winevt/Logs/Security.evtx` (4624/4625/4648/4672/4720/4728/1102), `System.evtx` (7045/104/6005/6006), `Microsoft-Windows-TaskScheduler%4Operational.evtx`, `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` (21/24/25) | `evtx` |
| Defender actions | `Microsoft-Windows-Windows Defender%4Operational.evtx` (5001/5007/1116/1117), `ProgramData/Microsoft/Windows Defender/Scans/History` | `evtx`, `ls` |
| Network and app usage per hour | `Windows/System32/sru/SRUDB.dat` | `esedb_tables`, `esedb_dump` |
| Indexed content, toast text, timeline | `ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb`, `Users/<u>/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db`, `.../ConnectedDevicesPlatform/<id>/ActivitiesCache.db` | `esedb_dump`, `sqlite_query` |
| Recent files, jump lists | `Users/<u>/AppData/Roaming/Microsoft/Windows/Recent/*.lnk`, `.../Recent/AutomaticDestinations` | `lnk`, `extract` |
| Browser history, logins, cache | `Users/<u>/AppData/Local/Microsoft/Edge/User Data/Default/{History,Login Data,Web Data,Cookies}`; Chrome same layout; Firefox `places.sqlite`, `formhistory.sqlite` | `sqlite_tables`, `sqlite_query` |
| Mail caches | Outlook `.ost/.pst` (extract, parse externally), OWA offline WebSQL under the browser profile | `find`, `extract` |
| Memory remnants | `/pagefile.sys`, `/hiberfil.sys`, `/swapfile.sys`, `Windows/MEMORY.DMP`, `Windows/Minidump` | `grep_file`, `strings` |
| Deleted data | `$Recycle.Bin/<SID>/$I*` (original path/time) and `$R*` (content), deleted names via `find --deleted only`, unallocated via `grep_unallocated` and `recover_deleted` | `ls`, `read`, `grep_unallocated`, `recover_deleted` |
| Timestomping | compare `$STANDARD_INFORMATION` and `$FILE_NAME` times | `stat` (indicator field) |
| Hidden streams | files with `ads` in `ls`; read with `read(stream=...)` | `ls`, `read` |
| Pictures and documents | EXIF/XMP, trailing bytes, OOXML hidden text and revisions | `exif`, `file_info`, `office_parts` |

## Linux

| Question | Artefact | Tool |
|---|---|---|
| Identity | `/etc/hostname`, `/etc/os-release`, `/etc/timezone`, `/etc/netplan`, `/etc/network/interfaces` | `read` |
| Users and logins | `/etc/passwd`, `/etc/shadow`, `/var/log/auth.log*`, `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | `read`, `strings`, `extract` |
| Shell and editor history | `~/.bash_history`, `~/.mysql_history`, `~/.viminfo`, `~/.lesshst`, `~/.python_history` | `read` |
| Services and schedules | `/etc/systemd/system`, `/var/spool/cron`, `/etc/cron.*`, `/var/log/syslog*`, `/var/log/journal` (binary; strings) | `ls`, `read`, `strings` |
| Packages | `/var/log/apt/history.log*`, `/var/lib/dpkg/status` | `read`, `grep_file` |
| Web and app servers | `/var/log/nginx`, `/var/log/apache2`, app data directories, MySQL/PostgreSQL data | `read`, `grep_files`, `extract` |
| Swap | swap partition (`partitions` shows it): `grep_unallocated` scans the whole partition when no file system is present | `grep_unallocated` |
| Deleted files | `find --deleted only`, `recover_deleted`; ext4 journal via external tools | `find`, `recover_deleted` |

## Android

| Question | Artefact | Tool |
|---|---|---|
| Accounts | `/data/system_ce/0/accounts_ce.db`, `/data/system_de/0/accounts_de.db` | `sqlite_query` |
| Mail (Exchange/Gmail app) | `/data/data/com.google.android.gm/databases/*` and `files/body` | `sqlite_tables`, `ls`, `read` |
| Contacts, calls, SMS | `/data/data/com.android.providers.contacts/databases/contacts2.db`, `calllog.db`, `.../telephony/databases/mmssms.db` | `sqlite_query` |
| App usage and notifications | `/data/system/usagestats`, `/data/system_ce/0/notification_history` | `ls`, `read` |
| Browser | `/data/data/<browser>/app_chrome/Default/History` | `sqlite_query` |
| Media | `/data/media/0/DCIM`, `Download`, `Pictures`, `Screenshots` | `find`, `exif`, `file_info` |
| Wi-Fi and network | `/data/misc/wifi/WifiConfigStore.xml`, `/data/misc/apexdata/com.android.wifi` | `read` |
| Terminal apps | per-app `files/` and `shared_prefs/` | `ls`, `read` |

## Time handling

Every timestamp is returned twice: `utc` (ISO 8601) and `local` in the image's configured timezone. Timeline and event-log filters accept ISO strings; naive strings are interpreted in the image's timezone. Machines whose clock was set to another zone (common in VM-built cases) are handled by setting that image's `--tz` so the `local` column matches what the user saw.
