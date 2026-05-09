import socket
import uuid
import re

def collect_network_metrics():
    network = {}

    network['hostname']=socket.gethostname()
    network['ip-address']=socket.gethostbyname(socket.gethostname())
    network['mac-address']=':'.join(re.findall('..', '%012x' % uuid.getnode()))
        
    return network