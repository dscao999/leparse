#!/bin/bash
#
client_ip=$1
passwd=$2
#
if ! ping -c 3 $client_ip > /tmp/probe_error.log 2>&1
then
	echo "CITIZEN=0"
fi
if sshpass -p $passwd ssh -l lenovo $client_ip ls | fgrep rc-local.log >> /tmp/probe_error.log 2>&1
then
	echo "CITIZEN=1"
else
	echo "CITIZEN=0"
fi
exit 0
#
function ssh_trust()
{
	if ! sshpass -p "$passwd" ssh-copy-id lenovo@"$client_ip"
	then
		echo "CITIZEN=0"
		exit 1
	fi
}
#
#
function hostname_mod()
{
	oname=$(hostname)
	nname=$1
	sed -i -e "/127.0.1.1/a&\t $nname" /etc/hosts
	hostnamectl --static set-hostname $nname
	sed -i -e "/$oname/d" /etc/hosts
}
#
# chpasswd
#
cat <<EOD | python3 -
import os, sys

lockfile = '/run/lock/client_probe'

exit_code = 0
try:
    fobj = os.open(lockfile, os.O_WRONLY|os.O_CREAT|os.O_EXCL)
    fobj.write(str(os.getpid()))
except:
    exit_code = 1
print(f"Exit code: {exit_code}")
if exit_code == 0:
    os.close(fobj)
sys.exit(exit_code)
EOD
#
ls -l /run/lock/client_probe
#
#ssh 
