from scapy.all import sniff, IP, TCP, UDP
import logging

# Load rules from file
def load_rules(filename="rules.txt"):
    rules = {"block_ip": set(), "allow_ip": set(), "block_port": set(), "allow_port": set()}
    try:
        with open(filename) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                action, rule_type, value = line.split()
                if action == "block":
                    rules[f"block_{rule_type}"].add(value)
                elif action == "allow":
                    rules[f"allow_{rule_type}"].add(value)
    except FileNotFoundError:
        print("No rules.txt found. No filtering will be done.")
    return rules

# Check if packet should be blocked or allowed
def check_packet(pkt, rules):
    if IP not in pkt:
        return False  # Not IP, ignore

    ip_src = pkt[IP].src
    ip_dst = pkt[IP].dst

    # Check IP rules
    if ip_src in rules["block_ip"] or ip_dst in rules["block_ip"]:
        return True  # Block

    if rules["allow_ip"]:
        if ip_src not in rules["allow_ip"] and ip_dst not in rules["allow_ip"]:
            return True  # Block because not explicitly allowed

    # Check ports for TCP/UDP
    if TCP in pkt or UDP in pkt:
        sport = pkt.sport
        dport = pkt.dport
        block_ports = {int(p) for p in rules["block_port"]}
        allow_ports = {int(p) for p in rules["allow_port"]}

        if sport in block_ports or dport in block_ports:
            return True  # Block

        if allow_ports and sport not in allow_ports and dport not in allow_ports:
            return True  # Block

    return False  # Allow

# Packet callback for sniffing
def packet_callback(pkt):
    if check_packet(pkt, rules):
        logging.warning(f"Blocked packet: {pkt.summary()}")
    else:
        print(f"Allowed packet: {pkt.summary()}")

if __name__ == "__main__":
    logging.basicConfig(filename="firewall.log", level=logging.WARNING,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    print("Loading rules...")
    rules = load_rules()
    print("Starting packet sniffing... Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)
