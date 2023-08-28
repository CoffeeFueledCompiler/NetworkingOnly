from scapy.all import sniff, Ether, IP
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# Initialize variables for packet count and timestamps
packet_count = 0
timestamps = []
packet_counts = []

def packet_handler(packet):
    global packet_count
    global timestamps
    global packet_counts

    packet_count += 1
    timestamps.append(datetime.now())
    packet_counts.append(packet_count)

    if Ether in packet:
        eth = packet[Ether]

        if IP in packet:
            ip = packet[IP]
            print(f"IP packet detected: Source {ip.src}, Destination {ip.dst}")

# Sniff packets using the filter parameter to capture all packets
def start_sniffing():
    sniff(filter="", prn=packet_handler, store=0)

# Create a time series plot
def animate(i):
    plt.cla()
    plt.plot(timestamps, packet_counts, marker='o')
    plt.xlabel('Time')
    plt.ylabel('Packet Count')
    plt.title('Packet Count Over Time')
    plt.xticks(rotation=45)
    plt.tight_layout()

# Start sniffing in a separate thread
import threading
sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.start()

# Animate the plot
ani = FuncAnimation(plt.gcf(), animate, interval=1000)

# Show the plot
plt.tight_layout()
plt.show()
