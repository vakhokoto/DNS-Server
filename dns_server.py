import sys, os
import socket, threading
from constants import *
from worker import worker
from easyzone import easyzone

server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
lock = threading.Lock()

def getZoneFiles(CONFIG):
    zFiles = []
    try:
        filenames = os.listdir(CONFIG)
        for zone in filenames:
            curZone = easyzone.zone_from_file(zone.split('.conf')[0], os.path.join(CONFIG, zone))
            zFiles.append(curZone)
            # print(curZone.names['example.com.'].records('A').items)
    except Exception:
        print('Error reading zonefiles\n')
    return zFiles

def run_dns_server(CONFIG, IP, PORT):
    zone = getZoneFiles(CONFIG)
    if os.path.exists(os.getcwd() + CONFIG) and not os.path.isfile(os.getcwd() + CONFIG):
        raise Exception("Invalid path provided")
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((IP, int(PORT)))
    while True:
        data, addr = server.recvfrom(CONTENT_LENGTH)
        workerThread = threading.Thread(target=worker, args=(data, server, addr, zone, lock))
        workerThread.start()

# do not change!
if __name__ == '__main__':
    CONFIG = sys.argv[1]
    IP = sys.argv[2]
    PORT = int(sys.argv[3])
    run_dns_server(CONFIG, IP, PORT)
