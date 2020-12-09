
#Importing the necessary modules
import logging
from datetime import datetime
import subprocess
import sys
import os
import time
basepath = os.path.dirname(__file__)

#This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


try:
    from scapy.all import *

except ImportError:
    print("Scapy package for Python is not installed on your system.")
    sys.exit()

def process_sniffed_packet(packet):
    #print(packet)
    # Check if our packet has HTTP layer. If our packet has the HTTP layer and it is HTTPRequest.
    # In this way I am excluding some garbage information in which I am not interested into.
    for pkt in packet:
        try:
            if pkt.haslayer(IP):
                return packet
                # ipsrc =pkt.getlayer(IP).src
                # print ipsrc
        except:
            raise
    

##########################################################################
#Where I handle sniffinf NIC. Note that root privilege is required to put interface in promiscous mode
#Note also that evironment variable for a user is different from the root
##########################################################################


def sniffPacket(interface, count):
    try:
        subprocess.call(["ifconfig", interface, "promisc"], stdout = None, stderr = None, shell = False)

    except:
        error_msg = "Failed to configure interface as promiscuous."
        return error_msg

    else:
        #Executed if the try clause does not raise an exception
        # print("\nInterface %s was set to PROMISC mode.\n" % net_iface)
        pass

    sniffed_packet = sniff(iface=interface, count=int(count))
    wrpcap("SniffedPacket2.pcap", sniffed_packet)
    os.system('tshark -r'+"SniffedPacket2.pcap" +'>'+ "SniffedPacket" +'.txt')
    time.sleep(3)
    with open("SniffedPacket.txt") as f:
        content = "".join(f.readlines())    
        # content = "<xmp> {} <xmp>".format("".join(f.readlines()))    
    # summary = sniffed_packet.summary()
    return content

def process_pcap_file(pcap_file):
    pcap_file = os.path.join(basepath,pcap_file)
    try:
        packets = rdpcap(str(pcap_file))
        sniffed_packet = process_sniffed_packet(packets)
        wrpcap("SniffedPacket2pcap", sniffed_packet)
        summary = sniffed_packet.summary()
        return summary
    except:
        raise
    # udp_packets = packets[UDP]
    #I am using sniff to process 1 packet at a time
    # try:
    #     packets = sniff(offline=str(pcap_file), prn=process_sniffed_packet)
    #     summary = packets.summary()
    #     return summary
    # except:
    #     error_msg = "Incorrect File format."
    #     return error_msg


    # return packets.show()
    







#Printing a message to the user; always use "sudo scapy" in Linux!
# print("\n! Make sure to run this program as ROOT !\n")


#Asking the user for some parameters: interface on which to sniff, the number of packets to sniff, the time interval to sniff, the protocol

#Asking the user for input - the interface on which to run the sniffer

# def sniffNIC(net_iface, proto_sniff=0, pkt_to_sniff=10, time_to_sniff=10):
#     try:
#         subprocess.call(["ifconfig", net_iface, "promisc"], stdout = None, stderr = None, shell = False)

#     except:
#         error_msg = "Failed to configure interface as promiscuous."
#         return error_msg

#     else:
#         #Executed if the try clause does not raise an exception
#         # print("\nInterface %s was set to PROMISC mode.\n" % net_iface)
#         pass
    
#     if proto_sniff == "0":
#         packets = sniff(iface = net_iface, count = int(pkt_to_sniff), timeout = int(time_to_sniff))

#     elif (proto_sniff == "arp") or (proto_sniff == "bootp") or (proto_sniff == "icmp"):
#         packets = sniff(iface = net_iface, filter = proto_sniff, count = int(pkt_to_sniff), timeout = int(time_to_sniff))
        
#     else:
#         # print("\nCould not identify the protocol.\n")
#         sys.exit()
    
#     wrpcap('filtered.pcap', packets, append=True)  #appends packet to output file

    #Printing the closing message
    # print("\n* Please check the %s file to see the captured packets.\n" % file_name)

    #Closing the log file
    # sniffer_log.close()



    #End of the program. 
    #Feel free to modify it, test it, add new protocols to sniff and improve de code whenever you feel the need to.

    # capture = raw_input("Enter file path of pcap file: " )
    # pcap = rdpcap(capture)

    # ports=137

    # def write(pkt):
    #     wrpcap('filtered.pcap', pkt, append=True)  #appends packet to output file

    # for pkt in pcap:
    #     if pkt.haslayer(UDP) and pkt.getlayer(UDP).sport == ports:  #checks for UDP layer and sport 137
    #         write(pkt)  #sends the packet to be written if it meets criteria
    #     else:
    #         pass

