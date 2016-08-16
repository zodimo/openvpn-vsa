#!/usr/bin/env python

import sys
import os
import atexit
from struct import *
import subprocess as sub
import re

ccd='/etc/openvpn/ccd'

firewall_type='iptables'


# test if paramter is passwd
if len(sys.argv) > 1:
	FIFO=sys.argv[1]
else:
	print ("pipename not found")
	sys.exit(1)


@atexit.register
def cleanup():
    try:
        os.unlink(FIFO)
    except:
        pass


def action_map(id):
	actions={
	0:'Authentication',
	1:'Client connect',
	2:'Client disconnect'
	}

	return actions[id]


def keyring_map(id):
	if id==0:
		return 'No'
	elif id==1:
		return 'yes'
	else:
		return 'undefined'



#	Attribute		Code
#-------------------------------------------
#  	username 		101			
#  	commonname 		102	
#	framedip 		103	
#	callingstationid 	104		
#	untrustedport 		105
#	framedroutes 		106		
#	vsabuf 			107

#	openvpn vendor id 27340
#	ATTRIBUTE	Openvpn-Client-Route			1	string
#	format IP NETMASK GATEWAY


debug=True


def debug(msg):
	if debug:
		print (msg)

def map_attribute(attribute_id):
	attributes={
	101:'username',
	102:'commonname',
	103:'framedip',
	104:'callingstationid',
	105:'untrustedport',
	106:'framedroutes',
	107:'vsabuf'
	}
	return attributes[attribute_id]


def main():
	if not os.path.exists(FIFO):
		os.mkfifo(FIFO)
	
	with open(FIFO) as fifo:		
		i = unpack('>i',fifo.read(4))  
		action=i[0]

		debug('###############################    START    ################################')

		debug( "Action :"+str(action_map(action)) )
		
		i = unpack('>i',fifo.read(4))        
		rekey=i[0]

		debug( "Rekeying :" + str(keyring_map(rekey)) )
		
		i = unpack('>i',fifo.read(4))    
		buflen = i[0]        
		print ("buflen before:"+str(buflen))
		
		buflen=buflen-12;


		while buflen > 0:
			debug(  "---------------------"	)
			debug(  'buflen  calculated:' + str(buflen) )
			i=unpack('>i',fifo.read(4))
			attribnumber=i[0]
			debug( "attribute number :"+str(attribnumber) )
			debug( "Attribute name :"+map_attribute(attribnumber) )

			i=unpack('>i',fifo.read(4))
			attriblen=int(i[0])
			debug( "attribute len :"+ str(attriblen) )



			if attribnumber == 107:
				while  attriblen > 0:
					debug( 'attriblen  calculated:' + str(attriblen ) )

					i=unpack('>i',fifo.read(4))
					vendor_id=i[0]
					debug( 'vendor_id:'+str(vendor_id) )
					i=unpack('B',fifo.read(1))
					vendor_attribnumber=i[0]
					debug( 'vendor_attribnumber:'+str(vendor_attribnumber) )
					i=unpack('B1',fifo.read(1))
					vendor_attriblen=int(i[0])-2
					debug( 'vendor_len:'+str(vendor_attriblen) )
					vendor_attribvalue=fifo.read(vendor_attriblen)
					debug( "vendor_attribvalue: "+str(vendor_attribvalue) )
					attriblen=attriblen-6-vendor_attriblen
					debug( 'attriblen calculated(end):' + str(attriblen) )
				debug('after vendor while...')
				break

			else:
				attribvalue=fifo.read(attriblen)
				if map_attribute(attribnumber)=='commonname':
					commonname=str(attribvalue)

				debug( "attribute value: "+str(attribvalue) )
				debug( "---------------------" )



			buflen=buflen-8-attriblen;
			debug( 'buflen calculated(end):-------------------------------' + str(buflen) )


			
main()
