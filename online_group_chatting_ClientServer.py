#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import struct
import ipaddress
import threading
import ast
import keyboard

########################################################################
# Multicast Address and Port
########################################################################

MULTICAST_ADDRESS = "239.0.0.10"
MULTICAST_PORT = 2000

# Make them into a tuple.
MULTICAST_ADDRESS_PORT = (MULTICAST_ADDRESS, MULTICAST_PORT)

# Ethernet/Wi-Fi interface address
IFACE_ADDRESS = "192.168.68.109"
# IFACE_ADDRESS = "172.18.131.122"  # change for ur machine's IPv4 address

CMD_FIELD_LEN = 1  # 1 byte commands sent from the client.
MSG_ENCODING = "utf-8"

# command dictionary
CMD = {
    "getdir": 1,
    "makeroom": 2,
    "deleteroom": 3,
    "connect": 4,
    "bye": 5,
    "name": 6,
    "chat": 7
}


########################################################################
# Multicast Server
########################################################################

class Server:
    # HOSTNAME = '0.0.0.0'
    HOSTNAME = socket.gethostname()

    CRDS_PORT = 44444

    CRDS_ADDRESS_PORT = (HOSTNAME, CRDS_PORT)

    TIMEOUT = 2
    RECV_SIZE = 256
    BACKLOG = 10

    CHAT_ROOMS = []  # list of chat rooms
    MSG_ENCODING = "utf-8"
    TTL = 1  # TLL 1 restricts to local subnetwork
    TTL_BYTE = TTL.to_bytes(1, byteorder='big')

    def __init__(self):
        self.thread_list = []  # list of client threads
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Get socket layer socket options.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind((Server.HOSTNAME, Server.CRDS_PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        self.socket.listen(Server.BACKLOG)
        print("Chat Room Directory Server listening on port {}...".format(Server.CRDS_PORT))
        try:
            while True:
                new_client = self.socket.accept()

                # A new client has connected. Create a new thread and
                # have it process the client using the connection
                # handler function.
                new_thread = threading.Thread(target=self.connection_handler, args=([new_client]))

                # Start the new thread running.
                print("Starting serving thread: ", new_thread.name)
                new_thread.daemon = True
                new_thread.start()

        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            print("Closing server socket ...")
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        ################################################################
        # Process a connection and see if the client wants a file that
        # we have.
        while True:
            # Receive bytes over the TCP connection. This will block
            # until "at least 1 byte or more" is available.
            recvd_bytes = connection.recv(CMD_FIELD_LEN)

            # Convert the command to our native byte order.
            cmd = int.from_bytes(recvd_bytes, byteorder='big')

            # If recv returns with zero bytes, the other end of the
            # TCP connection has closed (The other end is probably in
            # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
            # server end of the connection and get the next client
            # connection.
            if len(recvd_bytes) == 0:
                print("Closing {} client connection ... ".format(address_port))
                connection.close()
                # Break will exit the connection_handler and cause the
                # thread to finish.
                return

            print("Received: ", cmd)
            if cmd == CMD["getdir"]:
                print("Send:", str(Server.CHAT_ROOMS))
                connection.send(str(Server.CHAT_ROOMS).encode(Server.MSG_ENCODING))

            elif cmd == CMD["makeroom"]:
                recvd_bytes = connection.recv(Server.RECV_SIZE)
                recvd_list = recvd_bytes.decode(MSG_ENCODING).split()
                chat_room = recvd_list[0]
                address = recvd_list[1]
                port = recvd_list[2]
                print(recvd_list)
                found_flag = False

                for chatroom in self.CHAT_ROOMS:
                    if address == chatroom[1] and port == chatroom[2]:
                        found_flag = True
                        print("Address and Port Combination already in directory")
                        break

                if not found_flag:
                    self.CHAT_ROOMS.append(recvd_list)
                    print("Chat room:", chat_room, "added to Chat Room Directory (CRD)")

                invalid_room = found_flag.to_bytes(1, byteorder='big')
                connection.send(invalid_room)

            elif cmd == CMD["deleteroom"]:
                recvd_bytes = connection.recv(Server.RECV_SIZE)
                recvd_list = recvd_bytes.decode(MSG_ENCODING).split()
                chat_room = recvd_list[0]
                print('Delete Room:', chat_room)
                for chatroom in self.CHAT_ROOMS:
                    if chat_room == chatroom[0]:
                        self.CHAT_ROOMS.remove(chatroom)
                        print(chat_room, 'Deleted')


########################################################################
# Multicast Client
########################################################################

RX_IFACE_ADDRESS = IFACE_ADDRESS

##############################################
# Multicast receiver bind (i.e., filter) setup
##############################################
#
# The receiver socket bind address. This is used at the IP/UDP level to
# filter incoming multicast receptions. Using "0.0.0.0" should work
# ok. Binding using the unicast address, e.g., RX_BIND_ADDRESS =
# "192.168.1.22", fails (Linux) since arriving packets don't carry this
# destination address.
# 

# RX_BIND_ADDRESS = MULTICAST_ADDRESS # Ok for Linux/MacOS, not for Windows 10.
RX_BIND_ADDRESS = "0.0.0.0"

# Receiver socket will bind to the following.
RX_BIND_ADDRESS_PORT = (RX_BIND_ADDRESS, MULTICAST_PORT)


########################################################################

class Client:
    RECV_SIZE = 256
    # Create a 1-byte maximum hop count byte used in the multicast
    # packets (i.e., TTL, time-to-live).
    TTL = 1  # Hops
    TTL_BYTE = TTL.to_bytes(1, byteorder='big')

    def __init__(self):
        print("Bind address/port = ", RX_BIND_ADDRESS_PORT)

        self.name = ''
        self.get_socket()
        self.get_input()
        keyboard.hook(self.multicast_send_socket)  # start detecting key presses
        keyboard.wait()  # wait for key presses

    def get_socket(self):
        try:

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # self.socket.bind(RX_BIND_ADDRESS_PORT)

        except Exception as msg:
            print(msg)
            exit()

    def connect_to_server(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Connecting to:", Server.CRDS_ADDRESS_PORT)
        try:
            self.socket.connect(Server.CRDS_ADDRESS_PORT)
        except Exception as msg:
            print(msg)
            print("Closing...")
            sys.exit(1)

    def get_input(self):
        connection_established = False
        while True:
            try:
                self.input_text = input("\nEnter Command: ")
                self.input_text = self.input_text.split()
                self.input_command = self.input_text[0]

                if self.input_command in CMD:
                    cmd = CMD[self.input_text[0]]
                    if cmd:
                        print("Command Entered: " + self.input_command)

                    if cmd == CMD["getdir"]:
                        if connection_established:
                            self.get_directory()  # Need to send command to server
                        else:
                            print("Invalid Command! Connection not established with the server")

                    elif cmd == CMD["makeroom"]:
                        if connection_established:
                            chat_room_name = self.input_text[1]
                            address = self.input_text[2]
                            port = self.input_text[3]
                            print('Sending Request to make room:', chat_room_name, 'at address', address, 'and port', port)
                            make_room_info = (chat_room_name + ' ' + address + ' ' + port)
                            self.send_make_room_info(make_room_info)
                        else:
                            print("Invalid Command! Connection not established with the server")

                    elif cmd == CMD["deleteroom"]:
                        if connection_established:
                            chat_room_name = self.input_text[1]
                            self.delete_room_info(chat_room_name)
                        else:
                            print("Invalid Command! Connection not established with the server")

                    elif cmd == CMD["connect"]:
                        connection_established = True
                        print("Connecting to CRDS...")
                        self.connect_to_server()

                    elif cmd == CMD["bye"]:
                        if connection_established:
                            print("Closing server connection...")
                            self.socket.close()
                            connection_established = False
                        else:
                            print("Invalid Command! Connection not established with the server")

                    elif cmd == CMD["name"]:
                        self.name = self.input_text[1]

                    elif cmd == CMD["chat"]:
                        if self.name != '':
                            chat_room_name = self.input_text[1]
                            self.chat_mode(chat_room_name)
                        else:
                            print("Enter name <chat name> before chat <chat room name>")

                else:
                    print('Invalid Command')
                    continue

            except(KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection...")
                self.socket.close()
                sys.exit(1)

    def multicast_send_socket(self, address, port):

        self.exit_chat_mode = False

        def on_press(event):
            # print(event.name)
            if event.name == "ctrl":
                print("Exiting Chat Mode... ")
                self.exit_chat_mode = True
                keyboard.unhook_all()
                self.connect_to_server()
                self.get_input()

        try:
            while not self.exit_chat_mode:  # and not self.exit:
                keyboard.hook(on_press)  # check for keypress (ctrl)
                print('\nPlease Input your message: ')
                msg = input()
                if self.exit_chat_mode:
                    break
                msg = self.name + ": " + msg
                pkt = msg.encode(MSG_ENCODING)
                address_and_port = (address, port)
                print(address_and_port)
                self.socket.sendto(pkt, address_and_port)

        except KeyboardInterrupt:
            print("Exiting Chat Mode")

    def multicast_receive_msg(self, address, port):
        while True:
            try:
                data, address_port = self.socket.recvfrom(Client.RECV_SIZE)
                print("{}".format(data.decode(MSG_ENCODING)))
            except KeyboardInterrupt:
                print()
                exit()
            except Exception as msg:
                print(msg)
                sys.exit(1)

    def multicast_receive_socket(self, address, port):  # binding
        try:

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)

            ############################################################
            # Bind to an address/port. In multicast, this is viewed as
            # a "filter" that deterimines what packets make it to the
            # UDP app.
            ############################################################
            self.socket.bind((RX_BIND_ADDRESS, port))

            ############################################################
            # The multicast_request must contain a bytes object
            # consisting of 8 bytes. The first 4 bytes are the
            # multicast group address. The second 4 bytes are the
            # interface address to be used. An all zeros I/F address
            # means all network interfaces. They must be in network
            # byte order.
            ############################################################
            multicast_group_bytes = socket.inet_aton(address)
            print("Multicast Group: ", address)

            # Set up the interface to be used.
            multicast_iface_bytes = socket.inet_aton(RX_IFACE_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_iface_bytes
            # print("multicast_request = ", multicast_request)

            # Issue the Multicast IP Add Membership request.
            print("Adding membership (address/interface): ", MULTICAST_ADDRESS, "/", RX_IFACE_ADDRESS)
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_directory(self):
        cmd = CMD["getdir"].to_bytes(CMD_FIELD_LEN, byteorder='big')

        self.socket.send(cmd)
        self.dir = self.socket.recv(Client.RECV_SIZE).decode(MSG_ENCODING)
        if not dir:
            print("Directory List: EMPTY")
        else:
            print("Directory List: ", self.dir)

    def send_make_room_info(self, make_room_info):
        cmd = CMD["makeroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        pkt = cmd + make_room_info.encode(MSG_ENCODING)
        self.socket.send(pkt)

        invalid_room = self.socket.recv(Client.RECV_SIZE)
        invalid_room = bool.from_bytes(invalid_room, byteorder='big')

        if invalid_room:
            print("Address and Port Combination already in directory")

    def delete_room_info(self, chat_room_name):
        cmd = CMD["deleteroom"].to_bytes(CMD_FIELD_LEN, byteorder='big')
        pkt = cmd + chat_room_name.encode(MSG_ENCODING)
        self.socket.send(pkt)

    def chat_mode(self, chat_room_name):
        existing_chat_room = False
        self.get_directory()
        scan_dir = ast.literal_eval(self.dir)
        for chat_room in scan_dir:
            if chat_room_name == chat_room[0]:
                existing_chat_room = True
                chat_room_addr = chat_room[1]
                chat_room_port = int(chat_room[2])
                break

        if not existing_chat_room:
            print(f"Chat room: {chat_room_name} has not been created.")
            self.get_input()

        print("Entering chat mode...")
        self.multicast_receive_socket(chat_room_addr, chat_room_port)
        receive_thread = threading.Thread(target=self.multicast_receive_msg, args=(chat_room_addr, chat_room_port))
        receive_thread.daemon = True
        receive_thread.start()

        send_thread = threading.Thread(target=self.multicast_send_socket, args=(chat_room_addr, chat_room_port))
        send_thread.daemon = True
        send_thread.start()

        send_thread.join()
        receive_thread.join()


########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='Server or Client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
