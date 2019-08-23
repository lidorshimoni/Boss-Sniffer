import logging
logging.getLogger("scapy3k.runtime").setLevel(logging.ERROR)
from scapy3k.all import *
import urllib.request
import json
import subprocess


all_pac_data = []
your_ip = ""
ip_country_dict = {}

FILE_ADRESS = "setting.dat"

SERVER_IP = 'localhost'
SERVER_PORT = 6187


def is_udp_or_tcp(p):
    """return if this packet is UDP or TCP"""
    return IP in p and (TCP in p or UDP in p)


def get_your_ip():
    """get your ip by open socket with google"""
    global your_ip
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        your_ip = s.getsockname()[0]
    except Exception:
        pass
    finally:
        s.close()


def get_country_by_ip(ip):
    """get the ip country by HTTP GET from the site www.freegeoip.net"""
    if not ip in ip_country_dict:
        URL = "http://ip-api.com/json/" + ip + ""
        response = urllib.request.urlopen(URL)
        html = response.read()
        dict_json = json.loads(html)
        if dict_json["status"] == "fail":
            ip_country_dict[ip] = "Home"
        else:
            ip_country_dict[ip] = dict_json["country"]
    return ip_country_dict[ip]


def get_program_name(ip, port):
    """get the program name by netstat windows commend"""
    ans = subprocess.run(["netstat", "-nb"], stdout=subprocess.PIPE)
    nextLineBoll = False
    #print(ans)
    str1 = ip + ":" + str(port)
    for line in ans.stdout.decode().split("\n"):
        print(line)
        if nextLineBoll and len(line) < 20 and ".exe" in line:
            return line[2:-2]
        nextLineBoll = str1 in line
    return "Unknown"


def save_data(p_list):
    """save packet data to dic"""
    for p in p_list:
        incoming = your_ip == p[IP].dst
        size = len(p)
        if incoming:
            ip = p[IP].src
            if TCP in p:
                port = p[TCP].sport
                protocol = "TCP"
            else:
                port = p[UDP].sport
                protocol = "UDP"
        else:
            ip = p[IP].dst
            if TCP in p:
                port = p[TCP].dport
                protocol = "TCP"
            else:
                port = p[UDP].dport
                protocol = "UDP"
        p_name = get_program_name(ip, port)
        country = get_country_by_ip(ip)
        all_pac_data.append({"ip": ip, "country": country,
                             "incoming": incoming, "port": port, "size": size, "p_name": p_name, "protocol": protocol})


def send_data_to_server():
    """sending the data to the server"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (SERVER_IP, SERVER_PORT)
    sock.sendto(json.dumps(all_pac_data).encode(), server_address)
    sock.close()


def main():
    global all_pac_data
    get_your_ip()
    while True:
        print("_" * 20 + "\nStarting Sniff:")
        p_list = sniff(count=10, lfilter=is_udp_or_tcp)
        save_data(p_list)
        print("Sending The Data To The Server")
        try:
            send_data_to_server()
            print("Successful data transfer!")
        except Exception:
            print("Error while sending data!")
        finally:
            print("Clear Previous Data")
            all_pac_data = []


if __name__ == "__main__":
    main()
