# List available network interfaces
sudo python3 packet_analyzer.py --list

# Capture on specific interface
sudo python3 packet_analyzer.py -i eth0

# Capture specific number of packets
sudo python3 packet_analyzer.py -i eth0 -c 50

# Apply filter (e.g., only HTTP traffic)
sudo python3 packet_analyzer.py -i eth0 -f "tcp port 80"

# Capture only DNS traffic
sudo python3 packet_analyzer.py -i eth0 -f "udp port 53"
