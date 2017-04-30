#!/usr/bin/python
# -*- coding: utf-8 -*-
# author : Oros
# version : 2017/04/30

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


queries_liste={}

def process(pkt):
	if pkt.haslayer(DNSQR) and pkt[UDP].sport==53:
		# pkt[IP].dst == IP source of the DNS request
		# pkt[IP].src == IP of the DNS server
		# pkt[DNS].an.rrname == DNS name
		query=pkt[DNS].an.rrname if pkt[DNS].an != None else "?"

		if not pkt[IP].dst in queries_liste:
			queries_liste[pkt[IP].dst]={}

		if not pkt[IP].src in queries_liste[pkt[IP].dst]:
			queries_liste[pkt[IP].dst][pkt[IP].src]={}
		
		if not query in queries_liste[pkt[IP].dst][pkt[IP].src]:
			queries_liste[pkt[IP].dst][pkt[IP].src][query]=1
		else:
			queries_liste[pkt[IP].dst][pkt[IP].src][query]+=1

		system('clear')
		print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))
		for ip in queries_liste:
			print("{:15s}".format(ip)) # IP source
			for query_server in queries_liste[ip]:
				print(" "*18+"{:15s}".format(query_server)) # IP of DNS server
				for query in queries_liste[ip][query_server]:
					print(" "*36+"{:19s} {}".format(str(queries_liste[ip][query_server][query]),query)) # Count DNS request | DNS


parser = OptionParser(usage="%prog: [options]")
parser.add_option("-i", "--iface", dest="iface", default='', help="Interface")
(options, args) = parser.parse_args()

system('clear')
print("{:15s} | {:15s} | {:15s} | {}".format("IP source", "DNS server", "Count DNS request", "Query"))

if options.iface != "":
	sniff(filter='udp port 53', store=0, prn=process, iface=options.iface)
else:
	sniff(filter='udp port 53', store=0, prn=process)