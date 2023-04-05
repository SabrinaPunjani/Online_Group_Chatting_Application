# Online_Group_Chatting_Application
Online group chatting application with ability to create and join rooms, made in Python3 with Berkeley/POSIX socket API

A client/server network application that implements multi-group online chatting. The server code operates as a directory manager for online “chat rooms” that can be queried by the clients (i.e., the chat room users). The clients can dynamically create, delete and join chat rooms. After
joining a chat room, the client software exchanges messages with other clients using
IP multicast communications.

### License
MIT Open Source Initiative

# SETUP

open online_group_chatting_ClientServer.py in text editor and change the IFACE_ADDRESS at line 26 to your machine's Ethernet/WiFi interface address. 
If you do not know, it can be obtained with terminal comand ipconfig (windows) or ifconfig (Linux).

Start a terminal in the root folder and type python online_group_chatting_ClientServer.py -r Server to start a server or online_group_chatting_ClientServer.py -r Client to start a client. 

## Commands can be entered in the client windows as follows:

connect : The client connects to the Server, if connected you can execute Server cmds shown in Server section bellow

bye : This closes the client-to-CRDS connection, returning the user to the main command prompt.

name <chat name> : This command sets the name that is used by the client when
chatting, e.g., name Mel. All chat messages will be automatically prefixed with this
name, e.g., “Mel: Good morning!”.

chat <chat room name> : The client enters “chat mode” using the multicast
address/port for the associated chat room. Text typed at the command prompt is sent over the chat room. Text received from the
chat room is output on the command line.

While in chat mode, a defined control sequence ( <ctrl>) is used to exit chat
mode and return to the main prompt.

## Commands can be entered after connected to the server as follows:

getdir : The server returns a copy of the current chat room directory (CRD).
Each entry in the directory includes the chat room name, multicast IP adddress
and port.

makeroom <chat room name> <address> <port> : The server creates a chat room directory (CRD) entry that includes the above information. Note
that <address> is an IP multicast address used by the clients for chat messages
(Use the administratively scoped IP multicast range:
239.0.0.0 to 239.255.255.255).

deleteroom <chat room name> : The CRDS removes the chat room entry
from the CRD.

# SCREENSHOT:

![Alt text](https://i.imgur.com/hOENKUO.png)


