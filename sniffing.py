from wifi import Cell
from scapy.all import sniff

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

# Função para sniffing de tráfego
def sniff_traffic(interface):
    def packet_callback(packet):
        print(packet.summary())
    print(f"Sniffando pacotes na interface {interface}...")
    sniff(iface=interface, prn=packet_callback, count=10)

if __name__ == "__main__":
    interface = "wlan0"
    chosen_network = scan_and_choose_network(interface)
    
    if chosen_network:
        print(f"Iniciando sniffing de tráfego na rede {chosen_network['SSID']}...")
        sniff_traffic(interface)
