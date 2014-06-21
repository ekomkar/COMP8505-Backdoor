Packet Sniffing Backdoor Application
=====================================
How To Run
-----------
Before running the application there are few mandatory changes that are required, following is a list of things to change in “defs.h” file: <br />
- NET_DEVICE - Network interface card of the server [Default = em1]. <br />
- NETWORK_CARD - Network interface card of the client machine [Default = em1]. <br />
- DEF_FOLDER - The Directory that the server has to monitor [Default = /root/]. <br />
- DEF_SRC - IP address of local machine, client IP address if running as a client, server IP address if running as server. <br />
- DEF_DST - IP address of the remote machine, client IP address if running as a server, server IP address if running as client. <br />
- SLEEP_TIME - sleep duration between the exfiltrate packets sent by the server. [Default = 50000]. <br />

##Compile
Once the above changes are done, we can compile the application using the provided “Makefile”. In order to compile enter the command below and press Enter:
```
$> make clean
$> make
```
Once the application is compiled properly, an executable called “runner” will be created.

##Run Server / Backdoor
In order to run the application as a server/backdoor, run the command below:
```
$> ./runner -b
```
An optional switch “-w /root/Documents/” can be added to the command above in order to specify the folder to be watched by the backdoor. Run the command below, if you want to specify which folder to watch:
```
$> ./runner -b -w /root/Documents/
```
At this point the backdoor application should be running and should be watching the specified directory and the waiting to receive commands from the client.
##Run Client
In order to run the application as a client, run the command below:
```
$> ./runner -c
```
An optional switch “-x <tcp / udp>” can be added to the command above in order to specify the protocol to use for communication [Default = tcp]. Run the command below, if you want to specify which protocol to use: 
```
$> ./runner -c -x tcp
```
At this point client is running and should prompt the user to enter the command.

```
NOTE: The client will display the results of command sent by the user on the Terminal itself
and will write the contents of the modified files sent by the server in a file called result.log,
created in the same directory as the executable. 
```
