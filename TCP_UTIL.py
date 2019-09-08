'''
Filename: TCP_UTIL.py
Author: Andrew Roffee
Purpose: ...

Current TODO:
    I am now at the point I want to know what sort of TCP analysis I really want to do with the TCP_SESSION class. Right now I am researching what that might be. 
        Possibilities include:
        -Wiresharks TCP out of order analysis
        -TCP window size agreements
        -MSS agreements in the TCP handshake


Changes made:
    Started the file 
    Moved TCP_FLAGS from packetcap.py since this funcitonality does not have to be unique to packetcap
    Started the TCP_SESSION class design. 
        Added the functionality to pull separate one way tcp conversation data apart.

'''





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


#only takes the TCP data from packets, so each conversation from findtcpconversations will be fed into 
#pulltcpdatafromconversation() which will return a list which can then be fed into TCP_SESSION
#the list data will have the format of a list of tuples, (packet number, TCP tcp_payload)

class TCP_SESSION:
    def __init__(self, conversation):
        self.conversation = conversation
        self.session1, self.session2 =  self.getonewaysessions(self.conversation)
    
    #split the sessions based off source and destination port, ie one direction will have one src/dst pairing, and vice versa
    def getonewaysessions(self, convo):
        s1 = []
        s2 = []
        sport1 = convo[0][1].sport
        dport1 = convo[0][1].dport
        for tcp_payload in convo:
            if sport1 == tcp_payload[1].sport and dport1 == tcp_payload[1].dport:
                s1.append(tcp_payload)
            else:
                s2.append(tcp_payload)
        return s1,s2
TODO: FIGURE OUT WHY PACKET 0 IS PUT IN WRONG CONVO!!!!!!
    def __str__(self,):
        ran = len(self.session1) if len(self.session1)>len(self.session2) else len(self.session2)
        string_rep = 'Side1\t\t\t\tSide2\n'
        for x in range(ran):
            try:
                string_rep+=str(self.session1[x][1].seq)+' '+str(self.session1[x][1].ack)+'\t'
            except:
                pass
            try:
                string_rep+=str(self.session2[x][1].seq)+' '+str(self.session2[x][1].ack)+'\n'
            except:
                pass
        return string_rep


    #now to implement tcp analysis
    #def




#get sequence number difference
def seqdelta(num1,num2):
    return -1*(num1-num2)  


