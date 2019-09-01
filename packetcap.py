
''.join([chr(int(x,2)) for x in ethli[0][1].data.src]).decode('utf-8')        


import dpkt

f = open('c:\\users\\aroffee\desktop\\tvp_8_19.pcap','rb')
def grabpackets(fileLocation):
    f = open(fileLocation,'rb')
    pcap = dpkt.pcap.Reader(f)
    ethli = []
    for ts, buf in pcap:
        ethli.append((ts,dpkt.ethernet.Ethernet(buf)))
    return ethli
    

ip = eth.data
tcp = ip.data

#Get all Source IPs
for x in ethli:
    logger("Source IP: " +'.'.join(str(y) for y in x[1].data.src))
    #return '.'.join(str(y) for y in x[1].data.src)

#Get Destination IPs
for x in ethli:
    logger("Source IP: " +'.'.join(str(y) for y in x[1].data.dst))
    #return '.'.join(str(y) for y in x[1].data.dst

#Get Source ports
for x in ethli:
    logger(x[1].data.data.sport)

#Get Destination Ports
for x in ethli:
    logger(x[1].data.data.dport)

tcp.sport
tcp.dport
        
        
for x,y in enumerate(ethli):
    try:
        flags = TCP_FLAGS(ethli[x][1].data.data.flags)
    except:
        logger('',end='')
    finally:
        if len(bin(ethli[x][1].data.data.flags))<5:
            logger(str(x)+' '+str(flags.getflags()),end=' ')
            logger(bin(flags.getbits()))  

for x,y in enumerate(ethli):
    flags = TCP_FLAGS(ethli[x][1].data.data.flags)
    logger(str(x)+' '+str(flags.getflags()),end=' ')
    logger(bin(flags.getbits()))    

def getflag()

with open('c:\\users\\aroffee\\desktop\\sessionflags.txt','w') as flag:
    for x,y in enumerate(ethli):
        flags = TCP_FLAGS(ethli[x][1].data.data.flags)
        flag.write(str(x)+' '+str(flags.getflags()))
        flag.write(bin(flags.getbits())+'\n')


    for x in ethli:
        flag.write(str(bin(x[1].data.data.flags))+'\n')

'.'.join([str(x) for x in ethli[0][1].data.dst])

def decode(input):
    for x in input:
        try:
            x.decode('hex')
        except:
            logger.''

#Epoch time calculation (just going to do per interval)

January 1, 1970, 00:00:00 UTC

#packetcap.py

'''
End of tcp conversation ['FIN','PSH','ACK']

the sequence number of the ACK is the 
the ACK is +1 of the sending sequence number
[SYN] flag shows a new session
[SYN,ACK]

if see a syn this is a new session

otherwise it is an 
sample, this is a GRE packet_tup, each layer to peel back is another.data
Ethernet(dst=b'\xb0&\x80&\xa8\xc6', src=b'\x84=\xc6\x81\xcf\xc1', type=33024, 
vlan_tags=[VLANtag8021Q(pri=0, cfi=0, id=1200)], vlanid=1200, priority=0, cfi=0, data=IP(len=76, id=55026, 
ttl=255, p=47, sum=50514, src=b'\n\xa0\x02\t', dst=b'\n\xa0\x07\xf5', opts=b'', 
data=GRE(data=IP(len=52, id=10663, ttl=57, p=6, sum=47055, src=b'9\x0c\xf2\x8d', dst=b'\xd8q\x9cB', opts=b''
, data=TCP(sport=28600, dport=80, seq=2731555559, ack=2302139443, off=8, flags=24, sum=24576, 
opts=b'\x01\x01\x08\nI\xd9\x01E\x91-\xe6\xef')))))

>>> packets[0][1].data.data.data.data.seq
2731555559


def seedata(pac):
 logger(pac.data)
 try:
  seedata(pac.data)
 except:
  pass

def seedata1(pac):
    logger(pac.__repr__())
    try:
        seedata(pac.data)
    except:
        pass

pac.__repr__(), see all information as a string

57 -> 216
Seq             Ack
2968152311 SYN
2968152312 3915628781 ACK
2968152312 3915628781 HTTP POST
2968155208 3915628781 TCP previous segment not captured, Continuation or non HTTP traffic
2968153760 3915628781 TCP out of order
2968155474 3915631677 Acked unseen PSH ACK
2968155474 3915633125 Acked unseen PSH ACK
2968155474 3915634573 PSH ACK
2968155474 3915636021 PSH ACK
2968155474 3915638311 PSH ACK
2968155474 3915638311 FIN PSH ACK
2968155474 3915638312 PSH ACK

test instance
isinstance(packets[0][1],dpkt.ethernet.Ethernet)

packets1 is a newly read pacp file
for x,packet_tup in enumerate(packets1):
 try:
  if TCP_FLAGS(getvalue(packet_tup[1],'TCP','flags')).flagname == ['SYN','ACK']:
   logger("Found an syn ack packet_tup, its number is: "+str(x)+' sequence number is : '+str(getprotolayer(packet_tup[1],reverseindex(getprotocols(packet_tup[1]),'TCP')).seq))
 except:
  pass

#if TCP_FLAGS(getprotolayer(packet_tup[1],reverseindex(getprotocols(packet_tup[1]),'TCP')).flags).flagname == ['SYN','ACK']:  

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

'''


import sys
import dpkt 
import matplotlib.pyplot as plt


'''
I need an interface to pull protocol layers out of packets, while @getprotocols() gets what is there I need
to differentiate between traffic put in tunnels becuase there is a different source and destination IPs
depending if we are on the gre layer or lower. This will start at the lowest layer and work back, since 
someone will most often be interested in the bottom IP layer rather than GRE ip source and destination

@see getprotocols(), used by getvalue to list the protocol layers in a packet_tup
@see reverseindex()
@see getprotolayer()
@see getvalue()
'''

packetfields = {'ethernet':dpkt.ethernet.Ethernet,'tcp':dpkt.tcp.TCP,'ip':dpkt.ip.IP,'gre':dpkt.gre.GRE,\
'icmp':dpkt.icmp.ICMP,'bgp':dpkt.bgp.BGP,'ipv6':dpkt.ip6.IP6}

#get a list of all the protocols in the 
def getprotocols(packet):
    layers = []
    if isinstance(packet,packetfields['ethernet']):
        layers.append('ETHERNET')
    elif isinstance(packet,packetfields['gre']):
        layers.append('GRE')       
    elif isinstance(packet,packetfields['ip']):
        layers.append('IP')
    elif isinstance(packet,packetfields['tcp']):
        layers.append('TCP')          
    elif isinstance(packet,packetfields['icmp']):
        layers.append('ICMP')  
    elif isinstance(packet,packetfields['bgp']):
        layers.append('BGP')
    elif isinstance(packet,packetfields['ipv6']):
        layers.append('IPV6')
    try:        
        #if its just bytes then we've hit the packet payload
        if isinstance(packet,bytes):
            layers.append("Bytes")
            return layers
        #if we hit below the bottom there should be an error and it return empty.
        return layers + getprotocols(packet.data)   
    except:
        return layers

#output example ['ETHERNET', 'IP', 'GRE', 'IP', 'TCP', 'HTTP']

#helper function - does a backwards lookup for the lowest layer that matches the name of the protocol
#used by getvalue
def reverseindex(list_, value):
    for x in range(len(list_)):
        if list_[-(x+1)] == value:
            return len(list_) - (x+1)

#helper function - need to pull a layer from a packet_tup, layersdown will come from getprotocols()
#used by getvalue
def getprotolayer(packet_tup,layersdown):
    if layersdown == 0:
        return packet_tup
    return getprotolayer(packet_tup.data, layersdown-1)


#packet object, protocol desired and the output of getprotocols() for the packet
def getvalue(packet, protocoltype, data_field):
    avail_protocols = getprotocols(packet)
    layer = getprotolayer(packet,reverseindex(avail_protocols,protocoltype))
    if data_field == 'src':
        return layer.src
    elif data_field == 'dst':
        return layer.dst
    elif data_field == 'flags':
        return layer.flags
    elif data_field == 'seq':
        return layer.seq
    elif data_field == 'ack':
        return layer.ack
    elif data_field == 'sport':
        return layer.sport
    elif data_field == 'dport':
        return layer.dport
    else:
        return 0

'''
This TCP_FLAGS class can be used to determine flags names from raw packet_tup data returned from the above
@see getvalue() called with the TCP protocoltype and the flags data_field
'''

class TCP_FLAGS:
    def __init__(self,bits):
        self.bits = bits
        self.flagname = self.getname(bits)
    def getname(self,binary):
        setbits = [int(x) for x in bin(binary)[2:].zfill(5)]
        final = []
        if setbits[4] and setbits[4] == 1:
            final.append('FIN')
        if setbits[3] and setbits[3] == 1:
            final.append('SYN')
        if setbits[2] and setbits[2] == 1:
            final.append('RST')
        if setbits[1] and setbits[1] == 1:
            final.append('PSH')
        if setbits[0] and setbits[0] == 1:
            final.append('ACK')  
        return final
    def getflags(self,):
        return self.flagname
    def getbits(self,):
        return self.bits


'''
class TCP_SESSION:
    def __init__(self,session_packets,packet_tup):
        self.sourceIP =  #source
        self.destIP =   #dest
        self.packets =      #associate packet_tup numbers with session.


I want each TCP session to hold a reference for all the packets associated with it, therefore I should be
able to call on this session object and see all the data for the packets in the session and therefore
troubleshoot by session.

#returns readable mac address from packet_tup.src when packet_tup is of type pkt.ethernet.Ethernet
def getMAC(bytesin):
    return ':'.join([bytesin.hex()[i:i+2] for i in range(0,len(bytesin.hex()),2)])


def getTCPSession(packets):
    sessions = []
    for packet_tup in packets:
        TCP_SESSION()
'''


#fileLocation = 'c:\\users\\aroffee\desktop\\tvp_8_19.pcap'
def grabpackets(fileLocation):
    f = open(fileLocation,'rb')
    pcap = dpkt.pcap.Reader(f)
    ethli = []
    for ts, buf in pcap:
        ethli.append((ts,dpkt.ethernet.Ethernet(buf)))
    return ethli

def grabpackets1(fileLocation):
    f = open(fileLocation,'rb')
    pcap = dpkt.pcapng.Reader(f)
    ethli = []
    for ts, buf in pcap:
        ethli.append((ts,dpkt.ethernet.Ethernet(buf)))
    return ethli

#time_param is the number of interval in each slice
def packetInterval(packetlist,time_param):
    deltaT = 0
    interval = [] #holds packet_tup number boundaries of each second
    for packetnumber in range(len(packetlist)-1):
        deltaT += packetlist[packetnumber+1][0]-packetlist[packetnumber][0]
        if deltaT>=time_param:
            interval.append(packetnumber)#put the packet_tup number where the next second happens
            deltaT = 0
    return interval

#interval is output from packetInterval() in seconds so minutes =60, hours = 60^2 days = 60^2*24
def getflagcounts(flagtype, packets, interval):
    count_per_interval = []
    start= 0
    total_for_current_interval = 0
    #if we are looking for overall packet_tup count
    if flagtype == 'None':
        for number in interval:
            for packetsection in range(start,number):
                total_for_current_interval+=1
            count_per_interval.append(total_for_current_interval)
            total_for_current_interval = 0
            start = number
        return count_per_interval
    else: #if we are looking fo specific tcp flags
        for number in interval:
            for packetsection in range(start,number):
                flags = TCP_FLAGS(packets[packetsection][1].data.data.flags)
                if flagtype == flags.getflags():
                    total_for_current_interval+=1
            count_per_interval.append(total_for_current_interval)
            total_for_current_interval = 0
            start = number
        return count_per_interval

'''
Method to parse tcp streams.

@see getvalue()

break is only going to break the immediate loop
'''  

#return an ordered list of tcp converstation, correlated by an dictionary, ordered by packet_tup no.
#packets are numbered already (packet_tup number, packet_tup data)
def findtcpconversations(packets,logging = False):
    sessiondb={}
    stop = 0
    for x,packet_tup in enumerate(packets):
    #breakpoint()
        try:
            stop = 0
            #1 if not tcp then pass the packet_tup
            if 'TCP' not in getprotocols(packet_tup[1]):
                stop = 1
                continue
            curr_seq, curr_ack = getvalue(packet_tup[1], 'TCP', 'seq'),getvalue(packet_tup[1], 'TCP', 'ack')
            #2 if the packet_tup is a SYN packet_tup(only), make a !!new session
            if TCP_FLAGS(getvalue(packet_tup[1], 'TCP', 'flags')).flagname == ['SYN']:
                stop = 2
                sessiondb[(curr_seq,curr_ack)] = [packet_tup]
                if logging:
                    logger("Packet #"+str(x)+"\n"+str(sessiondb[(curr_seq,curr_ack)])+'\n\n')
                continue
            #3 otherwise compare seq, ack to the keys already in sessiondb
            add=0
            for keys in sessiondb:
                #if there are matching sequence or ack numbers
                if curr_seq in keys or curr_ack in keys:
                    sessiondb[(curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(curr_seq,curr_ack)] += [packet_tup]
                    stop = 3
                    if logging:
                        logger("Packet #"+str(x)+"\n"+str(sessiondb[(curr_seq,curr_ack)]))
                        logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(curr_seq,curr_ack)]))+'\n\n')
                    add+=1
                    break
                #if the curr_seq or curr_ack is +1 of a current key pair
                elif curr_seq-1 in keys or curr_ack-1 in keys:
                    sessiondb[(curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(curr_seq,curr_ack)] += [packet_tup]
                    stop = 4
                    if logging:
                        logger("Packet #"+str(x)+"\n"+str(sessiondb[(curr_seq,curr_ack)]))
                        logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(curr_seq,curr_ack)]))+'\n\n')
                    add+=1
                    break
            #If none of the above, so not added yet this packet is in the conversation and we make a new one.
            if add == 0:
                sessiondb[curr_seq, curr_ack] = [packet_tup]
                stop = 5
                if logging:
                    logger("Packet #"+str(x)+"\n"+str(sessiondb[(curr_seq,curr_ack)]))
                    logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(curr_seq,curr_ack)])))
        except Exception as e:
                logger("Stopped @ packet#: "+str(x)+'\n')
                logger(str(e))
                return
    return sessiondb

def logger(string):
    with open('/Users/acroffee/Roffee/git/packet/log.txt','a+') as log:
        log.write(string+'\n')

def cleanlog():
    

see results
def debugconv(sessiondb, end):
    count = 0
    for key in sessiondb:
        if count == end:
            break
        logger(str(sessiondb[key])+'\n'+str(count))
        count+=1



#get sequence number difference
def seqdelta(num1,num2):
    return -1*(num1-num2)  


def main():
    #fileLocation = 'c:\\users\\aroffee\desktop\\tvp_8_19.pcap'
    #dont forget time_param for packetInterval, change time windows for occurances
    #mac ~/Roffee/
    #packets = grabpackets('/Users/acroffee/Roffee/git/packet/spike.pcap')
    packets = grabpackets('c:\\users\\aroffee\desktop\\tvp_8_19.pcap') #sys.arg[1]
    packets1 = grabpackets('c:\\users\\aroffee\desktop\\spike.pcap') #sys.arg[1]
    x_axis = packetInterval(packets,1)
    interval = len(packetInterval(packets)) 
    '''
    The idea here is to make sure that however we determine y_axis is dependent on x_axis, this keeps 
    the logic simple.
    '''
    #y_axis = getflagcounts(['RST','ACK'],packets,x_axis) 
    y_axis = 
    plt.plot(x_axis,y_axis)
    plt.show()

    



def findtcpconversations-old(packets):
    #breakpoint()
    sessiondb={}
    stop = 0
    for x,packet_tup in enumerate(packets):
        curr_seq, curr_ack = getvalue(packet_tup[1], 'TCP', 'seq'),getvalue(packet_tup[1], 'TCP', 'ack')
        stop = 0
        #1 if not tcp then pass the packet_tup
        if 'TCP' not in getprotocols(packet_tup[1]):
            stop = 1
        #2 if the packet_tup is a SYN packet_tup(only), make a !!new session
        elif TCP_FLAGS(getvalue(packet_tup[1], 'TCP', 'flags')).flagname == ['SYN']:
            stop = 2
            sessiondb[(curr_seq,curr_ack)] = [packet_tup]
            logger(str("Database length after run SYN only "+str(x)+": "+str(len(sessiondb[curr_seq, curr_ack]))))
        #3 otherwise compare seq, ack to the keys already in sessiondb
        else:
            for keys in sessiondb:
                logger(keys)
                #if there are matching sequence or ack numbers
                if curr_seq in keys or curr_ack in keys:
                    sessiondb[(curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(curr_seq,curr_ack)].append(packet_tup)
                    stop = 3
                    break
                #if the curr_seq or curr_ack is +1 of a current key pair
                elif curr_seq-1 in keys or curr_ack-1 in keys:
                    sessiondb[(curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(curr_seq,curr_ack)].append(packet_tup)
                    stop = 4
                    break
                #otherwise we are in the middle of the conversation and we make a new one.
                else:
                    sessiondb[curr_seq, curr_ack] = [packet_tup]
                    stop = 5
                    break
            logger(str("Database length after run "+str(x)+": "+str(len(sessiondb[curr_seq, curr_ack]))))
        logger("stop: "+str(stop))
    return sessiondb



dict[newkey] = dict[oldkey]