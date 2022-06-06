Running Whole-System Monitoring

Starting Linux Audit
===

To turn on auditing for the entire system, run the following command:

`sudo ./start_audit.sh`

To stop the service:
`sudo systemctl stop auditd`

The output logs will be stored at `/var/log/audit/audit.log`.


Shutdown Whole-System Monitoring
===

You can delete all the rules to turn off the monitoring.

`sudo auditctl -D`

Troubleshooting
===

1. Check the auditd logs using the following command:

`journalctl -u auditd`

2. You can check the status of the auditd daemon using

`sudo systemctl status auditd`

3. Finally, you may need to restart the service

`sudo systemctl restart auditd`

Verify Monitoring Status
===

#### Check for the correct rules

Run the command `auditctl -l`, which should have the output below:

```
jallen309@theia:~/log-compression/audit$ auditctl -l
-a always,exit -F arch=b64 -S open,openat -F key=prov
-a always,exit -F arch=b64 -S read -F key=prov
-a always,exit -F arch=b64 -S write -F key=prov
-a always,exit -F arch=b64 -S exit,exit_group -F key=prov
-a always,exit -F arch=b64 -S close -F key=prov
-a always,exit -F arch=b64 -S execve -F key=prov
```

#### Verify the size of the audit logs are growing

`ll  /var/log/audit/audit.log` run this command multiple
times to see if the size is growing.


#### Verify correct system calls are being logs

```
 sudo tail /var/log/audit/audit.log
type=CWD msg=audit(1547654875.661:33315): cwd="/home/jallen309/log-compression/audit"
type=PATH msg=audit(1547654875.661:33315): item=0 name="/etc/passwd" inode=33295888 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
type=PROCTITLE msg=audit(1547654875.661:33315): proctitle="-bash"
type=SYSCALL msg=audit(1547654875.661:33316): arch=c000003e syscall=3 success=yes exit=0 a0=3 a1=c9e a2=8000 a3=7f92368f15e0 items=0 ppid=4700 pid=5021 auid=826249 uid=826249 gid=826249 euid=0 suid=0 fsuid=0 egid=826249 sgid=826249 fsgid=826249 tty=pts0 ses=228 comm="sudo" exe="/usr/bin/sudo" key="prov"
type=PROCTITLE msg=audit(1547654875.661:33316): proctitle="-bash"
type=SYSCALL msg=audit(1547654875.661:33317): arch=c000003e syscall=0 success=no exit=-11 a0=6 a1=7ffd5fe35f40 a2=1 a3=7f92363052d0 items=0 ppid=4700 pid=5021 auid=826249 uid=0 gid=826249 euid=0 suid=0 fsuid=0 egid=826249 sgid=826249 fsgid=826249 tty=pts0 ses=228 comm="sudo" exe="/usr/bin/sudo" key="prov"
type=PROCTITLE msg=audit(1547654875.661:33317): proctitle="-bash"
type=CRED_REFR msg=audit(1547654875.661:33318): pid=5021 uid=0 auid=826249 ses=228 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'
type=SYSCALL msg=audit(1547654875.661:33319): arch=c000003e syscall=3 success=yes exit=0 a0=8 a1=0 a2=2 a3=690 items=0 ppid=4700 pid=5021 auid=826249 uid=0 gid=826249 euid=0 suid=0 fsuid=0 egid=826249 sgid=826249 fsgid=826249 tty=pts0 ses=228 comm="sudo" exe="/usr/bin/sudo" key="prov"
type=PROCTITLE msg=audit(1547654875.661:33319): proctitle="-bash"
```
