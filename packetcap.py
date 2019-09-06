'''
Filename: packetcap.py
Author: Andrew Roffee
Purpose: ...

CLASSES 
CLASS TCP_FLAGS - small class to interpret TCP flags returned from the dpkt TCP class

METHODS 
getprotocols() - recursive function to acquire the protocols layered within a packet, used by getvalue() to list the protocol layers in a packet_tup (returns a list of protocols)

reverseindex() - used to tell getprotolater() how many layers to drill down to get the appropriate data (returns an integer index of the desired layer)

getprotolayer() - returns the protocol object from dpkt desired out of the provided packet, this allows us to pull whatever protocol information from whatever packet we want

getvalue() - sits on top of getprotolayer() and allows you to pull individual data fields out of dpkt classess housed inside a packet ex IP src address (returns dpkt class data fields)

grabpackets() - used to pull the packet data and create the appropriate dpkt objects to encapulate the data. The different versions apply to the different file 
formats that the dpkt class can interpret, so far one for pcap and one for pcapng files. (returns a list of dpkt objects)

packetinterval() - this splits packets into groups based off the time interval provided to this method. For example, packets every 5 minutes for the duration of the capture, every
minute, second etc, the time period is a parameter so it is fully customizeable. Direct helper function for gettcpflagcounts() (returns a list of packet numbers(type int) which define the 
boundaries of the time slice provided to the function)

gettcpflagcounts() - this function reads the packets split into their time intervals by packetinterval() and then counts the apprioriate number of packets the the desired flag type included,
this returns a list of counts of the specific flag type for each interval

findtcpconversations() - this method reads a list of packets from @grabpackets() file and then pulls out all the different tcp conversations and returns them in a time ordered list

Current TODO:
    Add some basic TCP analysis for the tcp seesions harvested from findtcpconversations()
    Explore if more complexity in plotting trends is necessary for desired functionality, I suspect not

Changes made:
    TODO!!: add packet number so we can see what packet number it is in the packetlist. (to sessiondb)
    Changed getvlaue() to return entire data_field to support pulltcpdatafromconversation and this TCP_UTIL TCP_SESSION 

Epoch time calculation (just going to do per interval)
January 1, 1970, 00:00:00 UTC
packetcap.py
'''

import sys
import dpkt 
import time
import matplotlib.pyplot as plt
from TCP_UTIL import *

#used for reading pcap files
def grabpackets(fileLocation):
    f = open(fileLocation,'rb')
    pcap = dpkt.pcap.Reader(f)
    ethli = []
    for ts, buf in pcap:
        ethli.append((ts,dpkt.ethernet.Ethernet(buf)))
    return ethli

#used for reading pacpng files
def grabpackets1(fileLocation):
    f = open(fileLocation,'rb')
    pcap = dpkt.pcapng.Reader(f)
    ethli = []
    for ts, buf in pcap:
        ethli.append((ts,dpkt.ethernet.Ethernet(buf)))
    return ethli


packetfields = {'ethernet':dpkt.ethernet.Ethernet,'tcp':dpkt.tcp.TCP,'ip':dpkt.ip.IP,'gre':dpkt.gre.GRE,\
'icmp':dpkt.icmp.ICMP,'bgp':dpkt.bgp.BGP,'ipv6':dpkt.ip6.IP6}

#get a list of all the protocols in the, yes so far only 7 protocols are usable, this will expand as my usage expands.
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
    if data_field == None:#if none return the who protocol field and all its subfields
        return layer
    elif data_field == 'src':
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
    elif data_field == 'bytes':
        return layer.data
    else:
        return 0

#returns the x_axis if we want a packets per a time frame
def packetinterval(start_end_time,time_param):
    total_time = timedelta(start_end_time[0],start_end_time[1])
    interval = []
    for time_decimal in range(0,int(total_time)+time_param,time_param):
        interval.append(epochtogmt(time.gmtime(start_end_time[0]+time_decimal)))
    return (interval,time_param)

#interval is output from packetinterval() in seconds so minutes =60, hours = 60^2 days = 60^2*24
def gettcpflagcounts(packets, interval,flagtype='None'):
    count_per_interval = [0]*len(interval[0])
    start_time = packets[0][0]
    #if we are looking for overall packet per interval count
    if flagtype == 'None':
        for packet in packets:
            time = packet[0] - start_time
            count_per_interval[int(time/interval[1])]+=1
    else: #if we are looking fo specific tcp flags
        for packet in packets:
            try:
                time = packet[0] - start_time
                flags = TCP_FLAGS(getvalue(packet[1],'TCP','flags')).getflags() #make sure this is packet not packets
                if flagtype == flags:
                    count_per_interval[int(time/interval[1])]+=1
            except:
                pass
    return count_per_interval

'''
Method to parse tcp streams. Intersting note for later, the loop over the session keys is much more time efficient than the list version of this loop.
Might be a good idea to look @ bigTheta for this for learning pruposes. 

return an ordered list of tcp converstation, correlated by an dictionary, ordered by packet_tup no.
packets are numbered already (packet_tup number, packet_tup data)
breakpoint() - to use pydebug

'''


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
            packet_triple = (x,)+packet_tup
            #2 if the packet_tup is a SYN packet_tup(only), make a !!new session
            if TCP_FLAGS(getvalue(packet_tup[1], 'TCP', 'flags')).flagname == ['SYN']:
                stop = 2
                sessiondb[(stream_number,curr_seq,curr_ack)] = [packet_triple]
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
                    sessiondb[(keys[0],curr_seq,curr_ack)] += [packet_triple]
                    stop = 3
                    if logging:
                        logger("Packet #"+str(x)+"\n"+str(sessiondb[(stream_number,curr_seq,curr_ack)]))
                        logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(stream_number,curr_seq,curr_ack)]))+'\n\n')
                    add+=1
                    break
                #if the curr_seq or curr_ack is +1 of a current key pair
                elif curr_seq-1 in keys[1:] or curr_ack-1 in keys[1:]:
                    sessiondb[(keys[0],curr_seq,curr_ack)] = sessiondb.pop(keys)
                    sessiondb[(keys[0],curr_seq,curr_ack)] += [packet_triple]
                    stop = 4
                    if logging:
                        logger("Packet #"+str(x)+"\n"+str(sessiondb[(stream_number,curr_seq,curr_ack)]))
                        logger('Conversation added to: '+str((curr_seq,curr_ack))+'\n'+'Number of items in the conversation: '+str(len(sessiondb[(stream_number,curr_seq,curr_ack)]))+'\n\n')
                    add+=1
                    break
            #If none of the above, make a !!new session
            if add == 0:
                sessiondb[(stream_number,curr_seq,curr_ack)] = [packet_triple]
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
    fin_db = [[x,sessiondb[x]] for x in keylist]
    print("Findtcpconversations took "+str(time.time()-t)+" seconds and "+str((time.time()-t)/60)+" minutes.")
    return fin_db

def logger(string):
    with open('/Users/acroffee/Roffee/git/data/log.txt','a+') as log:
        log.write(string+'\n')


def pulltcpdatafromconversation(tcp_conversation):
    tcp_convo = []
    for packets in tcp_conversation:
        tcp_portion = getvalue(packets[2],'TCP',None)
        tcp_convo.append((packets[0],tcp_portion)) #packet number,tcp payload including header
    return tcp_convo

#takes seconds since the epoch and converts to local time
def epochtolocal(timein):
    return time.ctime(timein)

#takes a time strucutre from time.ctime(decimal time)
def epochtogmt(timein):
    return time.strftime('%Y-%m-%d %H:%M:%SZ',timein)

def timedelta(time1, time2):
    return time2 - time1



def main():
    #fileLocation = 'c:\\users\\aroffee\desktop\\tvp_8_19.pcap'
    #dont forget time_param for packetinterval, change time windows for occurances
    #mac ~/Roffee/
    #   packets = grabpackets('/Users/acroffee/Roffee/git/data/spike.pcap')
    packets = grabpackets('c:\\users\\aroffee\desktop\\tvp_8_19.pcap') 
    packets1 = grabpackets('c:\\users\\aroffee\desktop\\spike.pcap') 
    x_axis = packetinterval((packets[0][0],packets[len(packets)-1][0]),10)
    interval = len(packetinterval(packets)) 

    '''
    The idea here is to make sure that however we determine y_axis is dependent on x_axis, this keeps 
    the logic simple.
    '''
    y_axis = gettcpflagcounts(packets, x_axis ,flagtype='None')
    y_axis = gettcpflagcounts(packets, x_axis, flagtype=['RST','ACK']) 
    counted = 'Issue counted ie tcp flag types' #this will become a parameter or soemthing changed based off of user selection
    y_axis = 

    plt.subplot #possibly use to manipulate axies and figure, not sure if there is an easier way yet https://matplotlib.org/api/_as_gen/matplotlib.pyplot.subplots.html#matplotlib.pyplot.subplots
    

    plt.plot(x_axis[0],y_axis)
    #change plot asthetics
    plt.xlabel('Time in GMT')
    plt.ylabel(counted)
    plt.xticks(rotation=90)
    plt.xticks.
    plt.title() #provide an overall graph title
    plt.setp(axis.YAxis.axis_name='Time in GMT')#testing not sure how to use yet

    plt.show()
    plt.show(block=plt1)#use block keyword to designate the .polt() list created with plt.plot(x,y)
    



