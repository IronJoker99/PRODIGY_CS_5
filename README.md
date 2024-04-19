# PRODIGY_CS_5
# Network Packet Analyzer

## Description
This is a basic packet sniffer tool implemented in Python using the `scapy` library. It captures and analyzes network packets, displaying relevant information such as source and destination IP addresses, protocols, and payload data.

## Ethical Use
- **Educational Purpose:** This tool is intended for educational purposes only. Use it to learn about network protocols and packet analysis.
- **Consent:** Always obtain explicit consent before using this tool on a network. Unauthorized packet sniffing may violate privacy laws and ethical standards.

## Usage
1. Run the `packet_sniffer.py` script.
2. Select the network interface to sniff packets on from the list of available interfaces.
3. Enter the number of packets to sniff.
4. The tool will sniff the specified number of packets on the specified interface and display relevant information.

## Requirements
- Python 3.x
- scapy library (install using `pip install scapy`)

## Example
python packet_sniffer.py
Available network interfaces:

    eth0
    wlan0
    enp2s0
    Select the interface to sniff packets on: 1
    Enter the number of packets to sniff: 10

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
