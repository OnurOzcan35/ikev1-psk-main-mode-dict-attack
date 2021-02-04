from scapy.all import *

def openPCAPFile(path):
    #TODO Your Code here
    try:
        return rdpcap(path)
    except:
        raise Exception("File is not found")

# returns only the ISAKMP Layer of the Packet
def getISAKMPPackets(packets):
    #TODO Your Code here
    packetList = []
    for packet in packets:
        try:
            packetList.append(packet["ISAKMP"])
        except:
            continue
    return packetList
