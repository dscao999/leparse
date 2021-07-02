#!/bin/bash
#
client_ip=$1
passwd=$2
if ! sshpass -p "$passwd" ssh-copy-id lenovo@"$client_ip"
then
	echo "CITIZEN=0"
	exit 1
fi
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
# chpasswd
ssh 
