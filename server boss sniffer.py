import socket
import json
import datetime

SERVER_IP = 'localhost'
SERVER_PORT = 6187

MAGSHIMIM_SERVER_IP = "54.71.128.194"
MAGSHIMIM_SERVER_PORT = 8808


FILE_ADRESS = "settings.dat"
TEMPLATE_FILE_ADRESS = r"""template\html\template.html"""
DONE_FILE_ADRESS = r"""template\html\example.html"""

IP_NUM_DICT = {}       # {ip : packet num } || example : {"8.8.8.8": 142}
COUNTRY_NUM_DICT = {}  # {country : packet num } || example : {"united state ": 523}
P_NAME_NUM_DICT = {}   # {program name : bytes num } || example : {"chrome.exe": 184875}
PORT_NUM_DICT = {}     # {port : packet num } || example : {"80": 456}
PROTOCOL_NUM_DICT = {}   # {protocol : packet num } || example : {"TCP": 974}
# {ip : incoming packet num } || example : {"127.0.0.1": 846}
INCOMING_PACKET_PER_USER = {}
# {ip : max size of packet } || example : {"127.0.0.1": 846}
MAX_SIZE_PER_USER = {}
# {ip : outgoing packet num } || example : {"127.0.0.1": 846}
OUTGOING_PACKET_PER_USER = {}
# list of users who get in blacklist || example : [("127.0.0.1",'157.240.1.119')]
BLACKLIST_USERS = []


def get_blacklist():
    is_blacklist = False
    s = []
    with open(FILE_ADRESS, 'r') as f:
        for line in f.read().split("\n"):
            if is_blacklist:
                s.append(line.split(":")[0])
            elif line == "blackList:":
                is_blacklist = True
    return s


def upload_report():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    msgshimim_server_address = (MAGSHIMIM_SERVER_IP, MAGSHIMIM_SERVER_PORT)
    sock.connect(msgshimim_server_address)
    sock.sendall("400#USER=kaki".encode())
    server_msg = sock.recv(1024).decode()
    print(server_msg)
    if "OK" in server_msg:
        html_file = open(DONE_FILE_ADRESS).read()
        import os
        size = str(os.path.getsize(DONE_FILE_ADRESS))
        msg = "700#SIZE=" + size + ",HTML=" + html_file
        sock.sendall(msg.encode())
        server_msg = sock.recv(1024).decode()
    else:
        print("Error while uploading")
    sock.close()


def get_users_name():
    s = {}
    with open(FILE_ADRESS, 'r') as f:
        for line in f.read().split("\n"):
            if line == "blackList:":
                return s
            s[line.split(":")[0]] = line.split(":")[1]


def add_to_dict(dict1, key, size=1):
    """add 1 to counter in dict"""
    print((key))
    if key in dict1:
        dict1[key] += size
    else:
        dict1[key] = size


def get_data(p, client_ip):
    print(p)
    """orgenize the data from the client to data base"""
    name = get_users_name()[client_ip]
    add_to_dict(IP_NUM_DICT, p['ip'])
    add_to_dict(COUNTRY_NUM_DICT, p['country'])
    add_to_dict(P_NAME_NUM_DICT, p['p_name'], p['size'])
    add_to_dict(PORT_NUM_DICT, p['port'])
    add_to_dict(PROTOCOL_NUM_DICT, p['protocol'])
    # incoming
    if p['incoming']:
        add_to_dict(INCOMING_PACKET_PER_USER, name)
    # outgoing
    else:
        add_to_dict(OUTGOING_PACKET_PER_USER, name)
    # blacklist
    for address in get_blacklist():
        if address == p['ip']:
            BLACKLIST_USERS.append((client_ip, p[IP]))
    # max size
    if name not in list(MAX_SIZE_PER_USER.keys()):
        MAX_SIZE_PER_USER[name] = p['size']
    elif p['size'] > MAX_SIZE_PER_USER[name]:
        MAX_SIZE_PER_USER[name] = p['size']


def reload_page():
    """from the data base to the html page"""
    with open(TEMPLATE_FILE_ADRESS, 'r') as f:
        temp = f.read()
        temp = temp.replace('%%TIMESTAMP%%', datetime.datetime.now().strftime("%d/%m/20%y"))

        # Incoming
        temp = temp.replace('%%AGENTS_IN_KEYS%%', str(list(INCOMING_PACKET_PER_USER.keys())))
        temp = temp.replace('%%AGENTS_IN_VALUES%%', str(list(INCOMING_PACKET_PER_USER.values())))
        # outgoing
        temp = temp.replace('%%AGENTS_OUT_KEYS%%', str(list(INCOMING_PACKET_PER_USER.keys())))
        temp = temp.replace('%%AGENTS_OUT_VALUES%%', str(list(OUTGOING_PACKET_PER_USER.values())))

        # Country
        temp = temp.replace("%%COUNTRIES_KEYS%%", str(list(COUNTRY_NUM_DICT.keys())))
        temp = temp.replace("%%COUNTRIES_VALUES%%", str(list(COUNTRY_NUM_DICT.values())))

        # Traffic Per IP
        temp = temp.replace("%%IPS_KEYS%%", str(list(IP_NUM_DICT.keys())))
        temp = temp.replace('%%IPS_VALUES%%', str(list(IP_NUM_DICT.values())))

        # Traffic Per App
        temp = temp.replace("%%APPS_KEYS%%", str(list(P_NAME_NUM_DICT.keys())))
        temp = temp.replace('%%APPS_VALUES%%', str(list(P_NAME_NUM_DICT.values())))


        # Traffic Per Port
        temp = temp.replace("%%PORTS_KEYS%%", str(list(PORT_NUM_DICT.keys())))
        temp = temp.replace('%%PORTS_VALUES%%', str(list(PORT_NUM_DICT.values())))

        # Traffic Per Protocol
        temp = temp.replace("%%PROTOCOL_KEYS%%", str(list(PROTOCOL_NUM_DICT.keys())))
        temp = temp.replace('%%PROTOCOL_DATA%%', str(list(PROTOCOL_NUM_DICT.values())))

        # Max Size of Packet Per User
        temp = temp.replace('%%MAX_PACKET_KEYS%%', str(list(MAX_SIZE_PER_USER.keys())))
        temp = temp.replace('%%MAX_PACKET_VALUES%%', str(list(MAX_SIZE_PER_USER.values())))

        # Alerts
        temp = temp.replace("%%ALERTS%%", str(BLACKLIST_USERS))
    with open(DONE_FILE_ADRESS, 'w') as f2:
        # Make File
        f2.write(temp)


def main():
    listening_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (SERVER_IP, SERVER_PORT)
    listening_sock.bind(server_address)
    try:
        while True:
            client_msg, client_addr = listening_sock.recvfrom(100000)
            for p in json.loads(client_msg):
                get_data(p, client_addr[0])
            reload_page()
            print('_' * 20 + "\nPage Reloaded")
            upload_report()
            print("Report Uploaded to server!")
    except Exception as e:
        print(e)
    finally:
        listening_sock.close()



if __name__ == "__main__":
    main()
