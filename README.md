🕵️ Network Sniffer
A Python-based network packet sniffer built using the Scapy library. This tool captures and analyzes real-time network traffic, displaying essential details such as source/destination IPs, protocols, ports, and payloads. It also supports packet counting, timestamps, TCP/UDP filtering, colorized console output, and logs for deeper analysis (e.g., via Wireshark).

🚀 Features
📡 Captures TCP and UDP packets in real-time.

🌐 Displays source/destination IPs, protocols, and ports.

🧾 Shows packet payloads (decoded in UTF-8 or hex format).

⏱ Includes packet counter and timestamps.

🎨 Colorized output for improved readability (via termcolor).

📝 Logs captured data to sniffer_output.txt.

💾 Saves packets in PCAP format (sniffer_output.pcap) for Wireshark.

🐧 Built to run on Kali Linux (or any Linux distro) with root privileges.

🧰 Prerequisites
Operating System: Kali Linux or compatible Linux distributions.

Python 3: Check with python3 --version.

Scapy: pip3 install scapy

Termcolor (for colored console output): pip3 install termcolor

Root privileges: Use sudo to run the script.

Network Interface: Identify with ip link (e.g., eth0, wlan0).

🛠 Installation
bash
Copy
Edit
# Update your system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Install required libraries
pip3 install scapy termcolor

# Verify installations
python3 -c "import scapy, termcolor"
▶️ Usage
bash
Copy
Edit
# Clone the repository
git clone https://github.com/ARPRAHMAN/network-sniffer.git
cd network-sniffer

# Run the sniffer (replace 'eth0' with your actual interface)
sudo python3 network_sniffer.py eth0
Press Ctrl + C to stop sniffing. Output will be saved to:

sniffer_output.txt (human-readable log)

sniffer_output.pcap (for tools like Wireshark)

🧪 Example Output
yaml
Copy
Edit
[*] Starting network sniffer on interface eth0...
[*] Logging output to sniffer_output.txt and saving packets to sniffer_output.pcap

[+] Packet #1 Captured at 2025-07-10 18:54:23:
Source IP: 192.168.1.100
Destination IP: 8.8.8.8
Protocol: UDP (17)
Source Port: 12345
Destination Port: 53
Payload: 0x1234567890abcdef...
📁 Files
File	Description
network_sniffer.py	Basic version of the sniffer.
network_sniffer_enhanced.py	Enhanced version with filtering, timestamps, logging, and color output.
sniffer_output.txt	Captured packet log.
sniffer_output.pcap	PCAP file for analysis with Wireshark.

⚖️ Ethical Considerations
Use this tool responsibly.

Only sniff traffic on networks you own or have explicit permission to monitor.

Unauthorized packet sniffing may be illegal in your jurisdiction.

Never publish or share sensitive payload data.

📄 License
This project is licensed under the MIT License.



📬 Contact
For feedback or inquiries:
contact.me.arifur@gmail.com
