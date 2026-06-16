import scapy.all
ip = "192.168.56.1"
ports =[53,80]
honeys = [8080,8443]

blocked = []

def analyzePacket(p) :
    
    global blocked
    print("Packet received!")
    if p.haslayer(scapy.all.IP):
        response = scapy.all.Ether(src=p[scapy.all.Ether].dst , dst=p[scapy.all.Ether].src)/scapy.all.IP(src=p[scapy.all.IP].dst, dst=p[scapy.all.IP].src)/scapy.all.TCP(src=p[scapy.all.TCP].dport, dport=p[scapy.all.TCP].sport,ack=p[scapy.all.TCP].seq+1)
        source = p[scapy.all.IP].src
    else:
        response = scapy.all.Ether(src=p[scapy.all.Ether].dst , dst=p[scapy.all.Ether].src)/ scapy.all.IPv6(src=p[scapy.all.IPv6].dst, dst=p[scapy.all.IPv6].src)/scapy.all.TCP(src=p[scapy.all.TCP].dport, dport=p[scapy.all.TCP].sport,ack=p[scapy.all.TCP].seq+1)
        source = p[scapy.all.IPv6].src
    if p[scapy.all.TCP].flags != "S":
        return
    port = p[scapy.all.TCP].dport
    print("Port:", port)
    if source in blocked:
        if port in ports:
            response[scapy.all.TCP].flags ="RA"
            print("sending reset")
        elif port in honeys:
            response[scapy.all.TCP].flags ="SA"
        else:
            return
        scapy.all.sendp(response,verbose=False)
    else:
        if port not in ports:
            blocked += [source]
            if port in honeys:
               
                response[scapy.all.TCP].flags ="SA"
                scapy.all.sendp(response,verbose=False)
f = "tcp" 
scapy.all.sniff(filter=f,prn=analyzePacket)
                  
           