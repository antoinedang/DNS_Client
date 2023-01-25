import sys
import socket
import random

class DNSPackets:
    def __init__(self):
        pass

    def encode(self, arguments):
        msg_id = random.getrandbits(16).to_bytes(2, byteorder='big')
        qr = '0'
        opcode = '0000'
        tc = '0'
        aa = '0'
        rd = '1'
        ra = '0'
        z = '000'
        rcode = '0000'
        qdcount = '0000000000000001'
        ancount = '0000000000000000'
        nscount = '0000000000000000'
        arcount = '0000000000000000'
        bit_string = qr + opcode + tc + aa + rd + ra + z + rcode + qdcount + ancount + nscount + arcount
        header_bytes = msg_id + self.bitstring_to_bytes(bit_string)

        split_labels = arguments["domain-name"].split(".")
        encoded_labels_string = ""
        for label in split_labels:
            encoded_labels_string += str(len(label))
            encoded_labels_string += label
        encoded_labels_string += '00000000'
        qname = bytes(encoded_labels_string, 'ascii')

        if arguments.get("type", None) == None:
            qtype = self.bitstring_to_bytes("0000000000000001")
        elif arguments.get("type") == "mail-server":
            qtype = self.bitstring_to_bytes("0000000000000010")
        else:
            qtype = self.bitstring_to_bytes("0000000000001111")

        qclass = self.bitstring_to_bytes("0000000000000001")

        question_bytes = qname + qtype + qclass

        return header_bytes + question_bytes

    def bitstring_to_bytes(self, s):
        return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

    def decode(self, packet):
        return None

class Socket:
    def __init__(self, timeout):
        #self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, msg):
        totalsent = 0
        MSGLEN = len(msg)
        while totalsent < MSGLEN:
            sent = self.sock.send(msg[totalsent:])
            totalsent = totalsent + sent

    def receive(self):
        chunk = self.sock.recv(2048)
        return b''.join([chunk])

    def close(self):
        # try this if problems
        # self.socket.shutdown() 
        self.sock.close()

def popByValue(l, val):
    try:
        l.remove(val)
        return l
    except ValueError:
        return l

def verifyIPValidity(ip):
    if "@" not in ip:
        print("ERROR\tIncorrect input syntax: IP Address must begin with @ character.")
        exit()
    elif len(ip.split(".")) != 4:
        print("ERROR\tIncorrect input syntax: IP Address is not in a.b.c.d form.")
        exit()
    else:
        for c in ip:
            if c in ".@": continue
            try:
                int(c)
            except Exception: 
                print("ERROR\tIncorrect input syntax: IP Address contains non-numerical characters.")
                exit()

def verifyValidity(name, val):
    if name == "timeout":
        try:
            if float(val) <= 0.0: 
                print("ERROR\tIncorrect input syntax: Timeout must be strictly positive.")
                exit()
        except Exception:
            print("ERROR\tIncorrect input syntax: Timeout must be a float.")
            exit()
    elif name == "port":
        try:
            int(val)
        except Exception:
            print("ERROR\tIncorrect input syntax: Port must be an integer.")
            exit()
    elif name == "max-retries":
        try:
            int(val)
        except Exception:
            print("ERROR\tIncorrect input syntax: Max retries must be an integer.")
            exit()


if __name__ == '__main__':
    arguments = {}
    nextArg = None
    for arg in sys.argv[1:]:
        if nextArg != None:
            verifyValidity(nextArg, arg)
            arguments[nextArg] = arg
            nextArg = None
            continue

        if arg == '-t':
            if len(arguments.keys()) != 0:
                print("ERROR\tIncorrect input syntax: Timeout argument must be the first argument.")
                exit()
            nextArg = "timeout"
        elif arg == '-r':
            if len(popByValue(list(arguments.keys()), "timeout")) > 0:
                print("ERROR\tIncorrect input syntax: Only timeout argument can be before max-retries argument.")
                exit()
            nextArg = "max-retries"
        elif arg == '-p':
            if len(popByValue(popByValue(list(arguments.keys()), "timeout"), "max-retries")) > 0:
                print("ERROR\tIncorrect input syntax: Only timeout or max-retries argument can be before port argument.")
                exit()
            nextArg = "port"
        elif arg == '-mx':
            if "type" in list(arguments.keys()):
                print("ERROR\tIncorrect input syntax: Cannot put both -mx and -ns arguments in same command.")
                exit()
            if len(popByValue(popByValue(popByValue(list(arguments.keys()), "timeout"), "max-retries"), "port")) > 0:
                print("ERROR\tIncorrect input syntax: Only timeout, max-retries, or port argument can be before MX argument.")
                exit()
            arguments["type"] = "mail-server"
        elif arg == '-ns':
            if "type" in list(arguments.keys()):
                print("ERROR\tIncorrect input syntax: Cannot put both -mx and -ns arguments in same command.")
                exit()
            if len(popByValue(popByValue(popByValue(list(arguments.keys()), "timeout"), "max-retries"), "port")) > 0:
                print("ERROR\tIncorrect input syntax: Only timeout, max-retries, or port argument can be before NS argument.")
                exit()
            arguments["type"] = "name-server"
        else:
            if arguments.get("server-name", None) == None:
                verifyIPValidity(arg)
                arguments["server-name"] = arg[1:]
            else:
                arguments["domain-name"] = arg

    if "server-name" not in list(arguments.keys()) or "domain-name" not in list(arguments.keys()):
        print("ERROR\tIncorrect input syntax: Server and domain name arguments are required.")
        exit()

    dns = DNSPackets()
    request = dns.encode(arguments)
    attempts = 0
    while attempts < int(arguments.get("max-retries", 3)):
        attempts += 1
        try:
            sock = Socket(float(arguments.get("timeout", 5)))
            sock.connect(arguments["server-name"], int(arguments.get("port", 53)))
            sock.send(request)
            response = sock.receive()
            dns.decode(response)
            sock.close()
            exit()
        except socket.timeout:
            continue
    print("ERROR\tMaximum number of retries ({}) exceeded.".format(arguments.get("max-retries", "3")))


