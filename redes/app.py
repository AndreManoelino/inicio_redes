import os
import socket
import subprocess
import time
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
from scapy.all import sr1, IP, ICMP, TCP
from collections import defaultdict
import dash
from dash import dcc, html, Input, Output, dash_table

app = dash.Dash(__name__)
# Configuração geral
NETWORKS = ["10.85.193", "172.16.50"]
DNS_SERVERS = ["10.85.193.9", "10.85.193.10", "172.16.50.3"]
PORTS_TO_SCAN = [80, 443, 22, 21, 25]  # Portas comuns
SCANNED_IPS = set()  # Armazenamento de IPs já escaneados para evitar duplicidade

# Função para capturar hostname
def get_hostname(ip):
    """Attempts to resolve the hostname with multiple retries."""
    for attempt in range(3):
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            time.sleep(0.5)
    return 'x'  # Retorna 'x' se o hostname não for resolvido

# Função para capturar latência média, mínima e máxima
def measure_latency(ip, attempts=5):
    """Measures average, min, and max latency over multiple attempts."""
    latencies = []
    for _ in range(attempts):
        response = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
        if response:
            latencies.append(response.time * 1000)  # Latência em ms
        time.sleep(0.2)
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        min_latency = min(latencies)
        max_latency = max(latencies)
        return avg_latency, min_latency, max_latency
    return None, None, None  # Se nenhuma resposta, retorna None

# Verificação de porta
def scan_ports(ip):
    """Scans specific ports to determine open services."""
    open_ports = []
    for port in PORTS_TO_SCAN:
        response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports

# Coleta informações detalhadas de um host
def collect_host_info(ip):
    """Collects information about a host, including hostname, latency, and open ports."""
    hostname = get_hostname(ip)
    if ip in SCANNED_IPS:
        return None  # Evita IP duplicado
    
    SCANNED_IPS.add(ip)  # Marca o IP como escaneado
    open_ports = scan_ports(ip)
    avg_latency, min_latency, max_latency = measure_latency(ip)

    # Verificação de status baseado na resposta de ping e tabela ARP
    is_active = bool(avg_latency)
    
    return {
        'IP': ip,
        'Hostname': hostname,
        'Status': 'Ativo' if is_active else 'Inativo',
        'Open Ports': open_ports,
        'Avg Latency (ms)': avg_latency,
        'Min Latency (ms)': min_latency,
        'Max Latency (ms)': max_latency,
    }

# Escaneia a rede completa
def scan_network(network):
    """Scans a full network range, collecting detailed information for each IP."""
    devices = []
    for i in range(1, 255):
        ip = f"{network}.{i}"
        host_info = collect_host_info(ip)
        if host_info:
            devices.append(host_info)
            print(f"IP: {ip} - Status: {host_info['Status']}")
    return devices

# Gerar relatório em Excel
def generate_excel_report(network_devices):
    """Generates an Excel report and a dashboard for all network devices."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"network_report_{timestamp}.xlsx"
    with pd.ExcelWriter(file_name) as writer:
        for network, devices in network_devices.items():
            df = pd.DataFrame(devices)
            df.to_excel(writer, sheet_name=f'Network_{network}')
            # Adiciona gráficos ao Excel
    print(f"Relatório salvo como: {file_name}")

# Criar Dashboard Avançado
def create_dashboard(network_devices):
    """Creates a visual dashboard for network device statistics."""
    # Unir todos os dispositivos em um DataFrame
    all_devices = [device for devices in network_devices.values() for device in devices]
    df = pd.DataFrame(all_devices)
    
    # Filtragem de ativos/inativos
    active_devices = df[df['Status'] == 'Ativo']
    inactive_devices = df[df['Status'] == 'Inativo']
    
    # Configuração do estilo de visualização
    sns.set(style="whitegrid")
    fig, axs = plt.subplots(2, 2, figsize=(15, 10))
    
    # Gráfico de barra de latências
    sns.barplot(data=active_devices, x="IP", y="Avg Latency (ms)", ax=axs[0, 0])
    axs[0, 0].set_title("Latência Média por IP Ativo")
    axs[0, 0].tick_params(axis='x', rotation=90)
    
    # Gráfico de pizza para ativos e inativos
    status_counts = df['Status'].value_counts()
    axs[0, 1].pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', startangle=140)
    axs[0, 1].set_title("Distribuição de Dispositivos Ativos e Inativos")
    
    # Gráfico de dispersão para latência mínima e máxima
    sns.scatterplot(data=active_devices, x="Min Latency (ms)", y="Max Latency (ms)", hue="Hostname", ax=axs[1, 0])
    axs[1, 0].set_title("Latência Minima vs Máxima para Dispositivos Ativos")
    
    # Gráfico de barras das portas abertas
    open_ports_counts = active_devices['Open Ports'].explode().value_counts()
    sns.barplot(x=open_ports_counts.index, y=open_ports_counts.values, ax=axs[1, 1])
    axs[1, 1].set_title("Contagem de Portas Abertas")
    axs[1, 1].set_xlabel("Porta")
    axs[1, 1].set_ylabel("Número de Dispositivos")

    plt.tight_layout()
    plt.show()

# Função principal para rodar o escaneamento completo
def main():
    network_devices = defaultdict(list)
    for network in NETWORKS:
        print(f"Scanning network: {network}")
        devices = scan_network(network)
        network_devices[network].extend(devices)
    
    # Geração do relatório e dashboard
    generate_excel_report(network_devices)
    create_dashboard(network_devices)

if __name__ == "__main__":
    main()
