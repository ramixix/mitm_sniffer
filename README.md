# mitm_sniffer
A man-in-the-middle attack is a **type of eavesdropping attack, where attackers interrupt an existing conversation or data transfer**. After inserting themselves in the "middle" of the transfer, the attackers pretend to be both legitimate participants.

In simple terms A man-in-the-middle (MitM) attack is when an attacker intercepts communications between two parties either to secretly eavesdrop or modify traffic traveling between the two. Attackers might use MitM attacks to steal login credentials or personal information, spy on the victim, or sabotage communications or corrupt data.
![](https://www.bettercap.org/legacy/assets/img/mitm.jpg)

### How man-in-the-middle attacks work
There are more than one technique that attackers can use to become a man-in-the-middle, I have used **ARP Cache Poisoning** here and it here how it works :  
**Address Resolution Protocol (ARP)** is a low-level process that translates the machine address (MAC) to the IP address on the local network.
Attackers inject false information into this system to trick your computer to think the attacker’s computer is the network gateway. When you connect to the network, the attacker is receiving all of your network traffic (instead of your real network gateway) and passes the traffic along to its real destination. From your perspective, everything is normal. The attacker is able to see all of your packets.  

**What we do in this piece of code? [steps]**  
**1. Attacker Finds the Mac address of gateway and Target host**  

**2. Attacker sends a packet to your computer with the faked source address of the gateway and the correct ARP sequence to fool your computer into thinking the attacker’s computer is the gateway**  

**3. At the same time, Attacker fool gateway into thinking the attacker’s computer is the host by sending fake arp packets.**  

**4. After fooling both gateway and target host attacker sniffs the specified packet number and write them to a pcap file.**
