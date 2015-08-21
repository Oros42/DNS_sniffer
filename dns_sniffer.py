#!/usr/bin/python
# -*- coding: utf-8 -*-
# author : Oros
# version : 2015/08/21

from os import system
from optparse import OptionParser
try:
	from scapy.all import sniff
	from scapy.all import ARP
	from scapy.all import DNSQR
	from scapy.all import UDP
	from scapy.all import IP
	from scapy.all import DNS
except ImportError:
	from sys import exit
	exit("\033[31mYou need to setup python-scapy\033[0m\nsudo apt-get install python-scapy")


dns_liste={}

def process(pkt):
	if pkt.haslayer(DNSQR) and pkt[UDP].sport==53:
		# pkt[IP].dst == IP source of the DNS request
		# pkt[IP].src == IP of the DNS server
		# pkt[DNS].an.rrname == DNS name
		dns=pkt[DNS].an.rrname if pkt[DNS].an != None else "?"

		if not pkt[IP].dst in dns_liste:
			dns_liste[pkt[IP].dst]={}

		if not pkt[IP].src in dns_liste[pkt[IP].dst]:
			dns_liste[pkt[IP].dst][pkt[IP].src]={}
		
		if not dns in dns_liste[pkt[IP].dst][pkt[IP].src]:
			dns_liste[pkt[IP].dst][pkt[IP].src][dns]=1
		else:
			dns_liste[pkt[IP].dst][pkt[IP].src][dns]+=1

		system('clear')
		print("IP source | DNS server | nb DNS request | DNS")
		for ip in dns_liste:
			print("{} :".format(ip)) # IP source
			for dns_server in dns_liste[ip]:
				print("\t{} :".format(dns_server)) # IP of DNS server
				for dns in dns_liste[ip][dns_server]:
					print("\t\t{}\t: {}".format(dns_liste[ip][dns_server][dns],dns)) # nb request | DNS


parser = OptionParser(usage="%prog: [options]")
parser.add_option("-i", "--iface", dest="iface", default='', help="Interface")
(options, args) = parser.parse_args()

system('clear')
print("IP source | nb request | DNS")

if options.iface != "":
	sniff(filter='udp port 53', store=0, prn=process, iface=options.iface)
else:
	sniff(filter='udp port 53', store=0, prn=process)