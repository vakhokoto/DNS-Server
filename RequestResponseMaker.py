import random
import struct, socket
from constants import *
from binascii import hexlify
import time, ipaddress
from ipaddress import v6_int_to_packed, v4_int_to_packed

def requestMaker(domain, typeOf, answers= 0, isResponse = 0):
    ID = random.randint(0, (1 << 16) - 1)
    ID = (ID, 256 | (isResponse << 15))
    fmt = struct.Struct("!H H")
    ID = fmt.pack(*ID)
    data = ID
    data += b"\x00\x01"
    fmt = struct.Struct("!H")
    ans = (answers,)
    data += fmt.pack(*ans)
    data += b"\00\x00\x00\x00"
    domain = domain.split('.')
    fmt = struct.Struct("!B")
    for s in domain:
        l = (len(s),)
        data += fmt.pack(*l)
        data += s.encode()
    if domain[-1] != '':
        data += b"\x00"
    fmt = struct.Struct("!H H")
    typeAndClass = (typeOf, IN)
    typeAndClass = fmt.pack(*typeAndClass)
    data += typeAndClass
    return data

def writeString(data, domain):
    domain = domain.split('.')
    fmt = struct.Struct("!B")
    for s in domain:
        l = (len(s),)
        data += fmt.pack(*l)
        data += s.encode()
    if domain[-1] != '':
        data += b"\x00"
    return data

def makeResponseForA(parsedData, IP, ttl= 60):
    ttl = int(ttl)
    domain = parsedData.domain
    typeOf = parsedData.qType
    IPData = v4_int_to_packed(IP._ip)
    data = requestMaker(parsedData.domain, parsedData.qType, 1, 1)
    data = writeString(data, parsedData.domain)
    fmt = struct.Struct("!H H I H")
    qT = (typeOf, IN, ttl, 4)
    data += fmt.pack(*qT)
    data += IPData
    return data

def makeResponseForAAAA(parsedData, IP, ttl= 60):
    ttl = int(ttl)
    typeOf = parsedData.qType
    IPData = v6_int_to_packed(IP._ip)
    data = requestMaker(parsedData.domain, parsedData.qType, 1, 1)
    data = writeString(data, parsedData.domain)
    fmt = struct.Struct("!H H I H")
    qT = (typeOf, IN, ttl, 16)
    data += fmt.pack(*qT)
    data += IPData
    return data

def makeResponseForMX(parsedData, MXInfo, ttl= 60):
    ttl = int(ttl)
    preferce, mailName = MXInfo
    typeOf = parsedData.qType
    data = requestMaker(parsedData.domain, parsedData.qType, 1, 1)
    data = writeString(data, parsedData.domain)
    newData = b''
    newData = writeString(newData, mailName)
    fmt = struct.Struct("!H H I H H")
    qT = (typeOf, IN, ttl, len(newData) + 2, preferce)
    data += fmt.pack(*qT)
    data += newData
    return data

def makeResponseForTXT(parsedData, TXT, ttl= 60):
    ttl = int(ttl)
    typeOf = parsedData.qType
    data = requestMaker(parsedData.domain, parsedData.qType, 1, 1)
    data = writeString(data, parsedData.domain)
    fmt = struct.Struct("!H H I H B")
    qT = (typeOf, IN, ttl, len(TXT) + 1, len(TXT))
    data += fmt.pack(*qT)
    data += TXT.encode()
    return data

def makeResponseForNS(parsedData, NSInfo, ttl= 60):
    ttl = int(ttl)
    typeOf = parsedData.qType
    data = requestMaker(parsedData.domain, parsedData.qType, 1, 1)
    data = writeString(data, parsedData.domain)
    fmt = struct.Struct("!H H I H")
    newData = b''
    newData = writeString(newData, NSInfo)
    qT = (typeOf, IN, ttl, len(newData))
    data += fmt.pack(*qT)
    data += newData
    return data
    

def makeResponseForSOA(parsedData, SOAInfo, ttl= 60):
    ttl = int(ttl)
    mName, rName, serial, refresh, retry, expire, minttl = SOAInfo
    typeOf = parsedData.qType
    data = requestMaker(parsedData.domain, parsedData.qType, 1, 1)
    data = writeString(data, parsedData.domain)
    newData = b''
    newData = writeString(newData, mName)
    newData = writeString(newData, rName)
    fmt = struct.Struct("!I I I I I")
    SOATTLInfo = (serial, refresh, retry, expire, minttl)
    newData += fmt.pack(*SOATTLInfo)
    fmt = struct.Struct("!H H I H")
    qT = (typeOf, IN, max(ttl, minttl), len(newData))
    data += fmt.pack(*qT)
    data += newData
    return data

def makeResponseForCNAME(parsedData, CNAME, ttl= 60):
    return makeResponseForNS(parsedData, CNAME, ttl)