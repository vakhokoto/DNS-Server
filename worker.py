import socket, random, datetime
import easyzone
from constants import *
from parser import Parser
from RequestResponseMaker import *
    

def getRandomRootIP():
    """
        returns random ROOT DNS IP
    """
    pos = random.randint(0, len(ROOT_DNSES) - 1)
    return ROOT_DNSES[pos]

def sendResponse(data, server, clientAddr, lock):
    lock.acquire()
    server.sendto(data, clientAddr)
    lock.release()

def alreadyHaveInfo(parsedData, zone):
    qCode = parsedData.qType
    qCodeName = "A"
    if qCode == TYPE_AAAA:
        qCodeName = "AAAA"
    elif qCode == TYPE_CNAME:
        qCodeName = "CNAME"
    elif qCode == TYPE_MX:
        qCodeName = "MX"
    elif qCode == "NS":
        qCodeName = "NS"
    elif qCode == TYPE_SOA:
        qCodeName = "SOA"
    elif qCode == TYPE_TXT:
        qCodeName = "TXT"
    for f in zone:
        try:
            if qCode == TYPE_SOA and f.domain == parsedData.domain and f.root.soa.serial != None:
                return f
            elif qCode != TYPE_SOA and f.names[parsedData.domain].records(qCodeName).items != None:
                return f
        except Exception:
            pass
    return None

def serveFromZone(parsedData, server, clientAddr, zone, lock):
    curZone = alreadyHaveInfo(parsedData, zone)
    qCode = parsedData.qType
    data = None
    if qCode == TYPE_A:
        data = makeResponseForA(parsedData, ipaddress.IPv4Address(curZone.names[parsedData.domain].records('A').items[0]))
    elif qCode == TYPE_AAAA:
        data = makeResponseForAAAA(parsedData, ipaddress.IPv6Address(curZone.names[parsedData.domain].records('AAAA').items[0]))
    elif qCode == TYPE_CNAME:
        data = makeResponseForCNAME(parsedData, curZone.names[parsedData.domain].records('CNAME').items[0])
    elif qCode == TYPE_MX:
        data = makeResponseForMX(parsedData, curZone.names[parsedData.domain].records('MX').items[0])
    elif qCode == TYPE_NS:
        data = makeResponseForNS(parsedData, curZone.names[parsedData.domain].records('NS').items[0])
    elif qCode == TYPE_SOA:
        soaData = curZone.root.soa.mname, curZone.root.soa.rname, curZone.root.soa.serial, curZone.root.soa.refresh, curZone.root.soa.retry, curZone.root.soa.expire, curZone.root.soa.minttl
        data = makeResponseForSOA(parsedData, soaData)
    elif qCode == TYPE_TXT:
        data = makeResponseForTXT(parsedData, curZone.names[parsedData.domain].records('TXT').items[0])
    newId = struct.pack('!H', parsedData.id)
    data = newId + data[2:]
    sendResponse(data, server, clientAddr, lock)

def checkCache(parsedData):
    if (parsedData.domain, parsedData.qType) not in cache:
        return False
    cacheTime, ttl, cachedData = cache[(parsedData.domain, parsedData.qType)]
    timeBetween = datetime.datetime.now() - cacheTime
    if timeBetween.total_seconds() < ttl:
        return True
    return False

def getResponse(sock, requestParsedData):
    data = b''
    parsedData = b''
    while True:
        try:
            data, addr = sock.recvfrom(CONTENT_LENGTH)
            parsedData = Parser(data)
            if parsedData.id != requestParsedData.id:
                continue
            else:
                break
        except Exception:
            continue
    return data, parsedData

def getResponseFromCache(parsedData, server, clientAddr, lock):
    domain, qType = parsedData.domain, parsedData.qType
    cacheTime, ttl, cachedData = cache[(domain, qType)]
    ttl = ttl - (datetime.datetime.now() - cacheTime).total_seconds()
    data = b''
    if qType == TYPE_A:
        data = makeResponseForA(parsedData, cachedData, ttl)
    elif qType == TYPE_AAAA:
        data = makeResponseForAAAA(parsedData, cachedData, ttl)
    elif qType == TYPE_CNAME:
        data = makeResponseForCNAME(parsedData, cachedData.decode(), ttl)
    elif qType == TYPE_MX:
        data = makeResponseForMX(parsedData, cachedData, ttl)
    elif qType == TYPE_NS:
        cachedData, = cachedData
        data = makeResponseForNS(parsedData, cachedData, ttl)
    elif qType == TYPE_SOA:
        data = makeResponseForSOA(parsedData, cachedData, ttl)
    else:
        data = makeResponseForTXT(parsedData, cachedData.decode(), ttl)
    newId = struct.pack('!H', parsedData.id)
    data = newId + data[2:]
    sendResponse(data, server, clientAddr, lock)

def worker(requestData, server, clientAddr, zone, lock, returnIP= False):
    """
        this is woker thread for serving a request
        starting from root DNS server
    """
    requestParsedData = Parser(requestData)
    if alreadyHaveInfo(requestParsedData, zone) != None:
        serveFromZone(requestParsedData, server, clientAddr, zone, lock)
        return
    elif checkCache(requestParsedData):
        if returnIP:
            cacheTime, ttl, ip = cache[(requestParsedData.domain, TYPE_A)]
            return str(ip)
        else:
            getResponseFromCache(requestParsedData, server, clientAddr, lock)
            return None
    data = requestData
    addr = getRandomRootIP()
    while True:
        addressFamily = socket.AF_INET
        try:
            socket.inet_pton(socket.AF_INET, addr)
        except Exception:
            addressFamily = socket.AF_INET6
        sock = socket.socket(addressFamily, socket.SOCK_DGRAM)
        sock.sendto(requestData, (addr, 53))

        # this is to check if response got from right source
        data, parsedData = getResponse(sock, requestParsedData)
        
        if parsedData.rCode != 0:
            sendResponse(data, server, clientAddr, lock)
            break
        elif parsedData.containsRecord((requestParsedData.domain, requestParsedData.qType)):
            if returnIP:
                return parsedData.getDomainDesiredInfo()
            else:
                sendResponse(data, server, clientAddr, lock)
                break
        else:
            addr = parsedData.getProperIP()
            if addr == None:
                NS = parsedData.getNS()
                if NS == None:
                    if returnIP:
                        return None
                    else:
                        sendResponse(data, server, clientAddr, lock)
                        break
                newData = requestMaker(NS, TYPE_A)
                addr = worker(newData, server, clientAddr, zone, lock, True)
                if addr == None:
                    if returnIP:
                        return None
                    else:
                        sendResponse(data, server, clientAddr, lock)
                        break
