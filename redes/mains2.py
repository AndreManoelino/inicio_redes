import os
import socket
import subprocess
import time
import pandas as pd
from datetime import datetime
from scapy.all import sr1, IP, ICMP, TCP

# Configuração geral
NETWORKS = ["10.85.193", "172.16.50"]
DNS_SERVERS = ["10.85.193.9", "10.85.193.10", "172.16.50.3"]
PORTS_TO_SCAN = [80, 443, 22, 21, 25]  # Portas comuns

# Função para ping com múltiplas tentativas
def ping_host(ip, attempts=5, timeout=1):
    """Pings multiple times to determine if a host is active."""
    successful_pings = 0
    for attempt in range(attempts):
        response = sr1(IP(dst=ip)/ICMP(), timeout=timeout, verbose=0)
        if response:
            successful_pings += 1
        time.sleep(0.2)  # Pequeno intervalo entre pings
    return successful_pings / attempts >= 0.5  # Considera ativo se 50%+ de tentativas tiverem sucesso

# Função para capturar hostname com múltiplas tentativas e fallback
def get_hostname(ip):
    """Attempts to resolve the hostname with multiple fallback mechanisms."""
    for attempt in range(3):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            time.sleep(0.5)  # Aumenta o tempo de espera antes de tentar novamente
    return 'x'  # Retorna 'x' se o hostname não for resolvido

# Função de verificação da tabela ARP
def check_arp(ip):
    """Verifies if an IP is in the ARP table as a fallback for active check."""
    arp_result = os.popen("arp -a").read()
    return ip in arp_result

# Scan de portas em um IP
def scan_ports(ip, ports=PORTS_TO_SCAN):
    """Scans specified ports on the host to determine open services."""
    open_ports = []
    for port in ports:
        response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports

# Função para coletar informações de rede de um IP específico
def collect_host_info(ip):
    """Collects comprehensive information about a host."""
    is_active = ping_host(ip)
    hostname = get_hostname(ip) if is_active else 'x'
    open_ports = scan_ports(ip) if is_active else []
    
    # Verifica fallback de tabela ARP se host está inativo
    if not is_active and check_arp(ip):
        is_active = True  # Atualiza status se está na tabela ARP
    
    # Verificação de latência média (múltiplos pings)
    latencies = []
    for i in range(3):
        response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if response:
            latencies.append(response.time * 1000)  # Latência em ms
    
    avg_latency = sum(latencies) / len(latencies) if latencies else None
    packet_loss = 100 - ((len(latencies) / 3) * 100)

    return {
        'IP': ip,
        'Hostname': hostname,
        'Status': 'Ativo' if is_active else 'Inativo',
        'Open Ports': open_ports,
        'Avg Latency (ms)': avg_latency,
        'Packet Loss (%)': packet_loss
    }

# Função principal para varrer uma rede
def scan_network(network):
    """Scans all hosts in a given network range."""
    devices = []
    for i in range(1, 255):
        ip = f"{network}.{i}"
        host_info = collect_host_info(ip)
        devices.append(host_info)
        print(f"IP: {ip} - Status: {host_info['Status']}")
    return devices

# Gerar relatório em Excel
def generate_excel_report(network_devices):
    """Generates an Excel report with all network devices' data."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"network_report_{timestamp}.xlsx"
    with pd.ExcelWriter(file_name) as writer:
        for network, devices in network_devices.items():
            df = pd.DataFrame(devices)
            df.to_excel(writer, sheet_name=f'Network_{network}')
            # Adiciona gráficos ao Excel
            # Implementação pode variar de acordo com o tipo de gráfico desejado
    print(f"Relatório salvo como: {file_name}")

# Função para rodar o escaneamento completo
def main():
    network_devices = {}
    for network in NETWORKS:
        print(f"Scanning network: {network}")
        devices = scan_network(network)
        network_devices[network] = devices
    
    # Geração do relatório final em Excel
    generate_excel_report(network_devices)

if __name__ == "__main__":
    main()
