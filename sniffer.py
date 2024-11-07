import requests
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest  
from scapy.all import get_if_list
import socket

hostname = socket.gethostname()
user_ip = socket.gethostbyname(hostname)

def packet_callback(packet):
    
    datafile = open("Ips.txt","a")
    f = 100
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if dst_ip != user_ip:
                datafile.writelines(str(dst_ip)+"\n")
                datafile.close()  
		
        print(f"[+] IP-пакет: {src_ip} -> {dst_ip}")
        
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[=]  TCP-пакет: Порт {src_port} -> {dst_port}")

            
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                method = http_layer.Method.decode()  
                host = http_layer.Host.decode() if http_layer.Host else ''
                path = http_layer.Path.decode() if http_layer.Path else ''
                url = f"http://{host}{path}"
                print(f"[-]   HTTP-запрос: {method} {url}")

        
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  UDP-пакет: Порт {src_port} -> {dst_port}")

def get_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        location = {
            "IP": ip,
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "Country": data.get("country", "Unknown"),
            "Location": data.get("loc", "Unknown"),
            "org": data.get("org", "Unknown")
        }
        return location
    except Exception as e:
        return {"ERROR": str(e)}


print(''' 
  ██████  ███▄    █  ██▓  █████▒       █████▒     
▒██    ▒  ██ ▀█   █ ▓██▒▓██   ▒      ▓██   ▒      
░ ▓██▄   ▓██  ▀█ ██▒▒██▒▒████ ░      ▒████ ░   Pidor-soft Inc.   
  ▒   ██▒▓██▒  ▐▌██▒░██░░▓█▒  ░      ░▓█▒  ░      by Monobehaviour
▒██████▒▒▒██░   ▓██░░██░░▒█░     ██▓ ░▒█░     ██▓ 0.8
▒ ▒▓▒ ▒ ░░ ▒░   ▒ ▒ ░▓   ▒ ░     ▒▓▒  ▒ ░     ▒▓▒ 
░ ░▒  ░ ░░ ░░   ░ ▒░ ▒ ░ ░       ░▒   ░       ░▒  
░  ░  ░     ░   ░ ░  ▒ ░ ░ ░     ░    ░ ░     ░   
      ░           ░  ░            ░            ░  
                                  ░            ░  
''')
print('adapters: ' + str(get_if_list()))
print('Your ip: ' + user_ip)
nigger = input('''
[1]Start sniffer
[2]Open last saved data file
[3]Get ip's location from last saved data file
''' + "\n") 
if nigger == "1":
        print("Starting...")
        sniff(prn=packet_callback, filter="ip", store=0)
if nigger == "2":
        datafile = open("Ips.txt")
        print(datafile.read())

#ip_address = dst_ip
#location_info = get_location(ip_address)
#print(location_info)