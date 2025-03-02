import os
import matplotlib.pyplot as plt
from scapy.all import IP, TCP, UDP, ICMP
from collections import Counter
import subprocess
from scapy.all import rdpcap, Raw
from scapy.layers.tls.record import TLS

# Define consistent color palette (same as before)
CAPTURE_COLORS = [
    "royalblue",
    "seagreen",
    "darkorange",
    "crimson",
    "purple"
]

PROTOCOL_COLORS = {
    "TCP": "cornflowerblue",
    "UDP": "mediumseagreen"
}


def get_average_packet_size(pcap_file):
    packets = rdpcap(pcap_file)
    total_size = sum(len(pkt) for pkt in packets)
    return total_size / len(packets) if len(packets) > 0 else 0


def get_average_ttl(pcap_file):
    packets = rdpcap(pcap_file)
    ttl_values = [pkt[IP].ttl for pkt in packets if IP in pkt]
    return sum(ttl_values) / len(ttl_values) if ttl_values else 0


def get_protocol_distribution(pcap_file):
    packets = rdpcap(pcap_file)
    protocol_counts = {"TCP": 0, "UDP": 0}

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                protocol_counts["TCP"] += 1
            elif UDP in pkt:
                protocol_counts["UDP"] += 1

    total_ip_packets = sum(protocol_counts.values())
    if total_ip_packets > 0:
        for proto in protocol_counts:
            protocol_counts[proto] = (protocol_counts[proto] / total_ip_packets) * 100

    return protocol_counts


def get_most_frequent_ports(pcap_file):
    packets = rdpcap(pcap_file)
    port_counter = Counter()

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                port_counter[pkt[TCP].sport] += 1  # Source port
                port_counter[pkt[TCP].dport] += 1  # Destination port
            elif UDP in pkt:
                port_counter[pkt[UDP].sport] += 1  # Source port
                port_counter[pkt[UDP].dport] += 1  # Destination port

    most_common_ports = [port for port, _ in port_counter.most_common(4)]  # Top 4 frequent ports
    return most_common_ports


def get_port_usage_percentage(pcap_file, ports):
    packets = rdpcap(pcap_file)
    total_packets = len(packets)
    port_usage = {port: 0 for port in ports}

    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                if pkt[TCP].sport in ports:
                    port_usage[pkt[TCP].sport] += 1
                if pkt[TCP].dport in ports:
                    port_usage[pkt[TCP].dport] += 1
            elif UDP in pkt:
                if pkt[UDP].sport in ports:
                    port_usage[pkt[UDP].sport] += 1
                if pkt[UDP].dport in ports:
                    port_usage[pkt[UDP].dport] += 1

    # Calculate the usage percentages
    usage_percentages = [(count / total_packets) * 100 for count in port_usage.values()]
    return usage_percentages


# Function to get average TCP window size
def get_average_tcp_window_size(pcap_file):
    packets = rdpcap(pcap_file)
    window_sizes = [pkt[TCP].window for pkt in packets if TCP in pkt]

    return sum(window_sizes) / len(window_sizes) if window_sizes else 0


def process_all_captures(pcap_files):
    avg_packet_sizes = []
    avg_ttls = []
    protocol_distributions = []
    frequent_ports = []
    usage_percentages = []
    capture_names = []
    avg_tcp_window_sizes = []

    for pcap_file in pcap_files:
        capture_names.append(os.path.basename(pcap_file))
        avg_packet_sizes.append(get_average_packet_size(pcap_file))
        avg_ttls.append(get_average_ttl(pcap_file))
        protocol_distributions.append(get_protocol_distribution(pcap_file))

        ports = get_most_frequent_ports(pcap_file)
        frequent_ports.append(ports)
        usage_percentage = get_port_usage_percentage(pcap_file, ports)
        usage_percentages.append(usage_percentage)

        # Add the average TCP window size
        avg_tcp_window_sizes.append(get_average_tcp_window_size(pcap_file))

    return capture_names, avg_packet_sizes, avg_ttls, protocol_distributions, frequent_ports, usage_percentages, avg_tcp_window_sizes


def plot_avg_packet_size(capture_names, avg_packet_sizes):
    plt.figure(figsize=(12, 4))
    plt.bar(capture_names, avg_packet_sizes, color=CAPTURE_COLORS)
    plt.ylabel("Average Packet Size (Bytes)")
    plt.title("Average Packet Size Comparison")
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()


def plot_avg_ttl(capture_names, avg_ttls):
    plt.figure(figsize=(12, 4))
    plt.bar(capture_names, avg_ttls, color=CAPTURE_COLORS)
    plt.ylabel("Average TTL")
    plt.title("Average TTL Comparison")
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()


def plot_protocol_distribution(capture_names, protocol_distributions):
    num_captures = len(capture_names)
    bar_width = 0.25
    x = range(num_captures)

    tcp_percentages = [dist["TCP"] for dist in protocol_distributions]
    udp_percentages = [dist["UDP"] for dist in protocol_distributions]

    plt.figure(figsize=(12, 6))

    plt.bar([pos - bar_width for pos in x], tcp_percentages, width=bar_width, label="TCP", color=PROTOCOL_COLORS["TCP"])
    plt.bar(x, udp_percentages, width=bar_width, label="UDP", color=PROTOCOL_COLORS["UDP"])

    plt.ylabel("Percentage of Packets (%)")
    plt.title("Protocol Distribution Comparison (TCP/UDP)")
    plt.xticks(x, capture_names, rotation=45)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.show()


def plot_most_frequent_ports(capture_names, frequent_ports, usage_percentages):
    num_captures = len(capture_names)
    bar_width = 0.2
    x = range(num_captures)

    port_labels = [f"Port {i + 1}" for i in range(4)]

    # Plot the graph for each port
    plt.figure(figsize=(12, 6))

    for i in range(4):  # There are 4 bars for each capture
        bars = plt.bar([pos + i * bar_width for pos in x],
                       [usage_percentages[j][i] for j in range(num_captures)],
                       width=bar_width, label=port_labels[i])

        # Annotate each bar with the usage percentage and the port number
        for j, bar in enumerate(bars):
            height = bar.get_height()
            port_number = frequent_ports[j][i]  # Get the port number for each bar
            # Annotate with percentage and port number
            plt.text(bar.get_x() + bar.get_width() / 2, height + 0.1, f"{port_number}",
                     ha='center', va='bottom', fontsize=10, color='black')

    plt.ylabel("Average Usage Percentage (%)")
    plt.title("Comparison of Top 4 Most Frequent Ports For Each Capture")
    plt.xticks(x, capture_names, rotation=45)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.show()


# New plot for comparing TCP window sizes
def plot_tcp_window_size(capture_names, avg_tcp_window_sizes):
    plt.figure(figsize=(12, 4))
    plt.bar(capture_names, avg_tcp_window_sizes, color=CAPTURE_COLORS)
    plt.ylabel("Average TCP Window Size")
    plt.title("Average TCP Window Size Comparison")
    plt.xticks(rotation=45)
    plt.grid(axis='y', linestyle='--', alpha=0.6)
    plt.tight_layout()
    plt.show()

def decrypt_pcap_in_memory(pcap_file, keylog_file):
    # Run tshark to decrypt the pcap file in memory and return the decrypted packets
    result = subprocess.run([
        "tshark",
        "-r", pcap_file,
        "-o", f"tls.keylog_file:{keylog_file}",
        "-T", "pdml"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error decrypting pcap file {pcap_file}: {result.stderr}")
        return []

    # Parse the decrypted pdml output (XML format)
    decrypted_packets = rdpcap(result.stdout)
    return decrypted_packets

def get_tls_version_usage(pcap_file, keylog_file):
    # Run tshark to decrypt the pcap file in memory and extract TLS records
    result = subprocess.run([
        "tshark",
        "-r", pcap_file,
        "-o", f"tls.keylog_file:{keylog_file}",
        "-Y", "tls.record.version",
        "-T", "fields",
        "-e", "tls.record.version"
    ], capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error decrypting pcap file {pcap_file}: {result.stderr}")
        return {"TLSv1.1": 0, "TLSv1.2": 0, "TLSv1.3": 0}

    # Parse the TLS versions used in the capture
    tls_versions = result.stdout.splitlines()
    version_count = {"TLSv1.1": 0, "TLSv1.2": 0, "TLSv1.3": 0}

    for version in tls_versions:
        if version == "0x0301":
            version_count["TLSv1.1"] += 1
        elif version == "0x0303":
            version_count["TLSv1.2"] += 1
        elif version == "0x0304":
            version_count["TLSv1.3"] += 1

    return version_count

def process_all_captures2(pcap_files, keylog_files):
    tls_version_usages = []
    capture_names = []

    for pcap_file, keylog_file in zip(pcap_files, keylog_files):
        capture_names.append(os.path.basename(pcap_file))

        # Get the TLS version usage for the capture
        version_usage = get_tls_version_usage(pcap_file, keylog_file)
        tls_version_usages.append(version_usage)

    return capture_names, tls_version_usages


# Function to plot TLS version usage for each capture
def plot_tls_version_usage(capture_names, tls_version_usages):
    num_captures = len(capture_names)
    bar_width = 0.2
    x = range(num_captures)

    tlsv1_1_usage = [usage["TLSv1.1"] for usage in tls_version_usages]
    tlsv1_2_usage = [usage["TLSv1.2"] for usage in tls_version_usages]
    tlsv1_3_usage = [usage["TLSv1.3"] for usage in tls_version_usages]

    plt.figure(figsize=(12, 6))

    # Plotting the bars for each TLS version
    plt.bar([pos - bar_width for pos in x], tlsv1_1_usage, width=bar_width, label="TLSv1.1", color="lightblue")
    plt.bar(x, tlsv1_2_usage, width=bar_width, label="TLSv1.2", color="lightgreen")
    plt.bar([pos + bar_width for pos in x], tlsv1_3_usage, width=bar_width, label="TLSv1.3", color="lightcoral")

    plt.ylabel("Usage Count")
    plt.title("TLS Version Usage Comparison for Each Capture")
    plt.xticks(x, capture_names, rotation=45)
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.show()

def main():
    pcap_files = [
        "firefox.pcapng",
        "google.pcapng",
        "spotify.pcapng",
        "youtube.pcapng",
        "zoom.pcapng"
    ]
    keylog_files = [
        "firefoxnew.log",
        "google.log",
        "spotify.log",
        "youtube.log",
        "zoom.log"
    ]

    print("Starting analysis...")

    # Process and analyze the captures
    capture_names, avg_packet_sizes, avg_ttls, protocol_distributions, frequent_ports, usage_percentages, avg_tcp_window_sizes = process_all_captures(pcap_files)

    # Plotting the results (using matplotlib)
    plot_avg_packet_size(capture_names, avg_packet_sizes)
    print("avg size")
    plot_avg_ttl(capture_names, avg_ttls)
    print("avg ttl")
    plot_protocol_distribution(capture_names, protocol_distributions)
    print("protocols")
    plot_most_frequent_ports(capture_names, frequent_ports, usage_percentages)
    print("ports")
    plot_tcp_window_size(capture_names, avg_tcp_window_sizes)
    print("window size")
    capture_names, tls_version_usages = process_all_captures2(pcap_files, keylog_files)

    # Plotting the TLS version usage
    plot_tls_version_usage(capture_names, tls_version_usages)
    print("TLS version usage plot created.")



if __name__ == "__main__":
    main()

