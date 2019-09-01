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

Epoch time calculation (just going to do per interval)
January 1, 1970, 00:00:00 UTC
packetcap.py
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
Method to parse tcp streams. Intersting note for later, the loop over the session keys is much more time efficient than the list version of this loop.
Might be a good idea to look @ bigTheta for this for learning pruposes. 
@see getvalue()

'''  

#return an ordered list of tcp converstation, correlated by an dictionary, ordered by packet_tup no.
#packets are numbered already (packet_tup number, packet_tup data)
#breakpoint() - to use pydebug
def findtcpconversations(packets,logging = False):
    t = time.time()
    sessiondb={}
    stop = 0
    stream_number = 0
    for x,packet_tup in enumerate(packets):
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
                sessiondb[(stream_number,curr_seq,curr_ack)] = [packet_tup]
                stream_number+=1
                if logging:
                    logger("Packet #"+str(x)+"\n"+str(sessiondb[(stream_number,curr_seq,curr_ack)])+'\n\n')
                continue
            #3 otherwise compare seq, ack to the keys already in sessiondb
            add=0
            for keys in sessiondb:
                #if there are matching sequence or ack numbers, keys[0] is the stream_number, this will not change with additional packets
                if curr_seq in keys[1:] or curr_ack in keys[1:]:
                    sessiondb[(keys[0],curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(keys[0],curr_seq,curr_ack)] += [packet_tup]
                    stop = 3
                    if logging:
                        logger("Packet #"+str(x)+"\n"+str(sessiondb[(stream_number,curr_seq,curr_ack)]))
                        logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(stream_number,curr_seq,curr_ack)]))+'\n\n')
                    add+=1
                    break
                #if the curr_seq or curr_ack is +1 of a current key pair
                elif curr_seq-1 in keys[1:] or curr_ack-1 in keys[1:]:
                    sessiondb[(keys[0],curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(keys[0],curr_seq,curr_ack)] += [packet_tup]
                    stop = 4
                    if logging:
                        logger("Packet #"+str(x)+"\n"+str(sessiondb[(stream_number,curr_seq,curr_ack)]))
                        logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(stream_number,curr_seq,curr_ack)]))+'\n\n')
                    add+=1
                    break
            #If none of the above, make a !!new session
            if add == 0:
                sessiondb[(stream_number,curr_seq,curr_ack)] = [packet_tup]
                stream_number+=1
                stop = 5
                if logging:
                    logger("Packet #"+str(x)+"\n"+str(sessiondb[(stream_number,curr_seq,curr_ack)]))
                    logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(stream_number,curr_seq,curr_ack)])))
        except Exception as e:
                logger("Stopped @ packet#: "+str(x)+'\n')
                logger(str(e))
                return
    print("Sorting")
    keylist = []
    for key in sessiondb:
        keylist.append(key)
    keylist.sort()
    findb = [[x,sessiondb[x]] for x in keylist]
    print("Findtcpconversations took "+str(time.time()-t)+" seconds and "+str((time.time()-t)/60)+" minutes.")
    return findb

def logger(string):
    with open('/Users/acroffee/Roffee/git/data/log.txt','a+') as log:
        log.write(string+'\n')

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
    #packets = grabpackets('/Users/acroffee/Roffee/git/data/spike.pcap')
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

    



