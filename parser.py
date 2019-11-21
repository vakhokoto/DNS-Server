import struct
from constants import *
import ipaddress
import datetime

class Parser:
    """
        This is a class for extracting DNS request into classes 
        to be easily treatable and understandable
    """
    def __init__(self, data):
        self.id = self._getId(data)
        self.isResponse = self._checkResponse(data)
        self.opCode = self._getOpCode(data)
        self.isAuthority = self._checkAuthority(data)
        self.isTruncated = self._checkTruncated(data)
        self.recursionDesired = self._isRecursionDesired(data)
        self.recursionAvailable = self._isRecursionAvailable(data)
        self.rCode = self._getRCode(data)
        self.qCount = 1
        self.ansNumber, self.NSCount, self.ARCount = self._getAnswerNumber(data)
        pointer = 12
        self.domain, pointer = getString(data, pointer)
        self.qType, pointer = self._getQType(data, pointer)
        pointer += 2
        print(";; ANSWERS SECTION:")
        self.answers, pointer = self._getAnswersList(data, pointer, self.ansNumber)
        print("\n;; AUTHORITIES ANSWERS SECTION:")
        self.authorities, pointer = self._getAnswersList(data, pointer, self.NSCount)
        print("\n;; ADDITIONALS SECTION:")
        self.additionals, pointer = self._getAnswersList(data, pointer, self.ARCount)

    def containsRecord(self, request):
        """
            checks if request is in any answers
        """
        return request in self.answers or request in self.authorities or request in self.additionals

    def _getAnswerNumber(self, data):
        """
            finds number of answers, nsresponses and also 
            additional answers in data
        """
        ansNum = (int(data[6]) << 8) + int(data[7])
        nsCount = (int(data[8]) << 8) + int(data[9])
        adCount = (int(data[10]) << 8) + int(data[11])
        return ansNum, nsCount, adCount

    def _getQType(self, data, pointer):
        """
            gets type of query
        """
        qType = (int(data[pointer]) << 8) + int(data[pointer + 1])
        return qType, pointer + 2

    def _getRCode(self, data):
        """
            finds request code for particular request
        """
        d = int(data[3])
        rCode = d & ((1 << 4) - 1)
        return rCode

    def _isRecursionAvailable(self, data):
        """
            check if recursio is available from server side
        """
        d = int(data[3])
        ind = (d >> 7) & 1
        return ind == 1

    def _isRecursionDesired(self, data):
        """
            checks if recursion is desired
        """
        d = int(data[2])
        ans = d & 1
        return ans == 1

    def _checkAuthority(self, data):
        """
            checks if source is authority
        """
        d = int(data[2])
        ans = (d >> 2) & 1
        return ans == 1

    def _checkTruncated(self, data):
        """
            checks if message was truncated
        """
        d = int(data[2])
        truncated = (d >> 1) & 1
        return truncated == 1

    def _checkResponse(self, data):
        """
            checks if data is response or Query
        """
        d = int(data[2])
        if (d >> 7) & 1:
            return True
        else:
            return False

    def _getOpCode(self, data):
        """
            this method determines the type of query(operation code)
        """
        d = int(data[2])
        opCode = (d >> 3) & ((1 << 4) - 1)
        return opCode

    def _getId(self, data):
        """
            this method gets request id from data
        """
        id = (int(data[0]) << 8) + int(data[1])
        return id

    def _getAnswersList(self, data, pointer, count):
        """
            gets list of answers from data
            searches from 'pointer' 

            Note: this method also used for authority answers additionals
        """
        answers = {}
        for i in range(0, count):
            curAnswerText, pointer = getString(data, pointer)
            typeOfAnswer = (int(data[pointer]) << 8) + int(data[pointer + 1])
            pointer += 4
            ttl = 0
            for j in range(0, 4):
                ttl = (ttl << 8) + int(data[pointer])
                pointer += 1
            rdLen = (int(data[pointer]) << 8) + int(data[pointer + 1])
            pointer += 2
            rData = ""
            print(curAnswerText + "\t" + str(ttl) + "\tIN\t", end = "")
            if typeOfAnswer == TYPE_CNAME:
                rData, p = getString(data, pointer)
                print("CNAME\t" + rData)
                rData = (rData,)
            if typeOfAnswer == TYPE_NS:
                rData, p = getString(data, pointer)
                print("NS\t" + rData)
                rData = (rData,)
            elif typeOfAnswer == TYPE_MX:
                rData, p = getMX(data, pointer)
                pref, exch = rData
                print("MX\t" + str(pref) + "\t" + exch)
            elif typeOfAnswer == TYPE_SOA:
                rData, p = getSOA(data, pointer)
                mName, rName, serial, refresh, retry, expire, minimum = rData
                st = str(serial) + "\t" + str(refresh) + "\t" + str(retry) + "\t" + str(expire) + "\t" + str(minimum)
                print("SOA\t" + mName + "\t" + rName + "\t" + st)
            elif typeOfAnswer == TYPE_TXT:
                rData, p = getTXT(data, pointer)
                print("TXT\t" + rData.decode("utf-8"))
            elif typeOfAnswer == TYPE_A:
                rData = ipaddress.IPv4Address(data[pointer:pointer+rdLen])
                print("A\t" + str(rData))
            elif typeOfAnswer == TYPE_AAAA:
                rData = ipaddress.IPv6Address(data[pointer:pointer+rdLen])
                print("AAAA\t" + str(rData))
            curAnsTuple = (curAnswerText, typeOfAnswer)
            if curAnsTuple not in answers:
                answers[curAnsTuple] = []
            cache[curAnsTuple] = (datetime.datetime.now(), ttl, rData)
            answers[curAnsTuple].append((ttl, rData))
            pointer += rdLen
        return answers, pointer

    def getIP(self, answers):
        """
            this method gets IP from answers
        """
        ip = None
        for text, typeOf in answers:
            if typeOf == TYPE_NS and (len(self.domain) > len(text) and self.domain.endswith("." + text) or self.domain == text):
                for ttl, NS in answers[(text, typeOf)]:
                    NS, = NS
                    ip = findIn(NS, self.answers)
                    if ip != None:
                        return ip
                    ip = findIn(NS, self.authorities)
                    if ip != None:
                        return ip
                    ip = findIn(NS, self.additionals)
                    if ip != None:
                        return ip
        return None

    def getProperIP(self):
        """
            this method gets back IP of the next server which 
            could have info about the request
        """
        ip = self.getIP(self.answers)
        if ip != None:
            return ip
        ip = self.getIP(self.authorities)
        if ip != None:
            return ip
        ip = self.getIP(self.additionals)
        if ip != None:
            return ip
        return None

    def getNS(self):
        """
            gets NS server name
        """
        NSName = findNSIn(self.domain, self.answers)
        if NSName != None:
            return NSName
        NSName = findNSIn(self.domain, self.additionals)
        if NSName != None:
            return NSName
        NSName = findNSIn(self.domain, self.authorities)
        if NSName != None:
            return NSName
        return None

    def getDomainDesiredInfo(self):
        """
            gets desired information
        """
        data = (self.domain, self.qType)
        ans = None
        if data in self.answers:
            ttl, ans = self.answers[data][0]
        elif data in self.additionals:
            ttl, ans = self.additionals[data][0]
        elif data in self.authorities:
            ttl, ans = self.authorities[data][0]
        return str(ans)

def findNSIn(domain, data):
    for name, typeOf in data:
        if typeOf == TYPE_NS and (len(domain) > len(name) and domain.endswith("." + name) or domain == name):
            for ttl, NS in data[(name, typeOf)]:
                NS, = NS
                if NS != None:
                    return NS
    return None

def findIn(NS, data):
    """
        finds IPV4 or IPV6 of NS in data
    """
    if (NS, TYPE_A) in data:
        ttl, ip = data[(NS, TYPE_A)][0]
        return str(ip)
    elif (NS, TYPE_AAAA) in data:
        ttl, ip = data[(NS, TYPE_A)][0]
        return str(ip)
    return None
        

def getTXT(data, pointer):
    """
        this is method for reading TXT data RDATA
        in 'data' from 'pointer'
    """
    l = int(data[pointer])
    pointer += 1
    txt = data[pointer:pointer + l]
    pointer += l
    return txt, pointer

def getSOA(data, pointer):
    """
        this is method for reading SOA data RDATA
        in 'data' from 'pointer'
    """
    fmt = struct.Struct("!I I I I I")
    mName, pointer = getString(data, pointer)
    rName, pointer = getString(data, pointer)
    serial, refresh, retry, expire, minimum = fmt.unpack(data[pointer:pointer + 20])
    pointer += 20
    return (mName, rName, serial, refresh, retry, expire, minimum), pointer

def getMX(data, pointer):
    """
        this is method for reading MX data RDATA
        in 'data' from 'pointer'
    """
    preference = (int(data[pointer]) << 8) + int(data[pointer + 1])
    pointer += 2
    exchange, p = getString(data, pointer)
    return (preference, exchange), pointer

def getString(data, pointer):
    """
        this is method for reading Name, QName and RData
        in 'data' from 'pointer'
    """
    ansName = ""
    while True:
        size = int(data[pointer])
        pointer += 1
        if size & (3 << 6) == (3 << 6):
            size <<= 8
            size += int(data[pointer])
            pointer += 1
            newString, p = getString(data, size ^ (3 << 14))
            ansName += newString
            break
        elif size == 0:
            break
        ansName += data[pointer:pointer + size].decode() + "."
        pointer += size
    if ansName == "":
        ansName = "."
    return ansName, pointer