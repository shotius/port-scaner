import nmap
import socket
import pprint
import services

# check if url exists
def good_netloc(netloc):
    try:
        socket.gethostbyname(netloc)
        return True
    except:
        return False

def get_open_ports(target, port_range, verbose = False):
	# if url is valid make scan
	if (good_netloc(target)):
		print('=========================================')
		print("scanning {} ...".format(target))
		print('scanning ports {}-{}'.format(port_range[0], port_range[1]))

		scanner = nmap.PortScanner()
		# third argument is given make verbose scan
		if (verbose):
			print("verbose scan")
			res = scanner.scan(target, '{}-{}'.format(port_range[0], port_range[1]), '-v')
		# else make simple scan
		else :
			res = scanner.scan(target, '{}-{}'.format(port_range[0], port_range[1]))
#		pprint.pprint(res)

		# dict of all open ports	
		open_ports = res['scan'][socket.gethostbyname(target)]['tcp'].keys()
		print('--------------------------------------------')
		print("open ports for {} ({})".format(target, socket.gethostbyname(target)))
		print(' PORT   SERVICE')

		# print open ports
		for port in open_ports:

			# if we have service name for specific port print this service as well
			if port in services.ports_and_services:
				print(' {}    {}'.format(port, services.ports_and_services[port]))
			else :
				print(' {}     -'.format(port))
		
		print('\n\n')
	else : 
		print("domain not found")


	open_ports = []



	return(1)


get_open_ports("104.26.10.78", [440, 450], True)
get_open_ports("104.26.10.78", [8079, 8090])
get_open_ports("www.freecodecamp.org", [75,85])
get_open_ports("137.74.187.104", [440, 450], True)
get_open_ports("scanme.nmap.org", [20, 80], True)
