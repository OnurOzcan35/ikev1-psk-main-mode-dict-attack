from scapy.all import *

ISAKMP_KEX_NAME = "ISAKMP Key Exchange"
ISAKMP_NONCE_NAME = "ISAKMP Nonce"

def getIniatorSAPacket(packets):
    #TODO Your Code here
    return packets[0]["ISAKMP"]

def getResponderSAPacket(packets):
    #TODO Your Code here
    return packets[1]["ISAKMP"]

# name == payload name
def getPayloadFromISAKMP(packet, name):
    # TODO Your Code here
    return packet[name].fields['load']

# forResponder == True/False
def getCookieFromISAKMP(packet, forResponder):
    # TODO Your Code here
    if (forResponder):
        return packet.fields['resp_cookie']
    else:
        return packet.fields["init_cookie"]

def getSAPayloadFromInitPacket(packet):
    # TODO Your Code here
    SaPacket = packet[1]
    ByteChange = bytes(SaPacket)
    ByteSize = SaPacket.length
    return ByteChange[4:ByteSize]

#def getResponderIDFromRespPacket(packet):
    # TODO Your Code here
    #aggressive dict attack
    #byteIdType = bytes([packet["ISAKMP Identification"].fields["IDtype"]])
    #byteProtoID = bytes([packet["ISAKMP Identification"].fields["ProtoID"]])
    #bytePort = packet["ISAKMP Identification"].fields["Port"].to_bytes(2, byteorder='little')
    #consist =b"".join([byteIdType, byteProtoID, bytePort, packet["ISAKMP Identification"].fields["load"]])
    #return consist

def getIPs(packets):
    #1.source 2. destination
    return [packets[0]["IP"].fields["src"], packets[0]["IP"].fields["dst"]]


def getEncryptedData(packets, senderIP):
    # TODO Your Code here
    encrypted = []
    for packet in packets:
        if(packet["IP"].fields["src"] == senderIP):
            if packet["ISAKMP"].flags == 1:
                    encrypted.append(packet["ISAKMP"].load)
    return encrypted

