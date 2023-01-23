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
        print(str(header_bytes))
        return None

    def bitstring_to_bytes(self, s):
        return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

    def decode(self, packet):
        return None

class Socket:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, msg):
        totalsent = 0
        while totalsent < MSGLEN:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent

    def receive(self):
        chunks = []
        bytes_recd = 0
        while bytes_recd < MSGLEN:
            chunk = self.sock.recv(min(MSGLEN - bytes_recd, 2048))
            if chunk == b'':
                raise RuntimeError("socket connection broken")
            chunks.append(chunk)
            bytes_recd = bytes_recd + len(chunk)
        return b''.join(chunks)

    def close(self):
        # try this if problems
        # self.socket.shutdown() 
        self.socket.close()

if __name__ == '__main__':
    arguments = {}
    nextArg = None
    for arg in sys.argv[1:]:
        if nextArg != None:
            arguments[nextArg] = arg
            nextArg = None
            continue

        if arg == '-t':
            nextArg = "timeout"
        elif arg == '-r':
            nextArg = "max-retries"
        elif arg == '-p':
            nextArg = "port"
        elif arg == '-mx':
            arguments["type"] = "mail-server"
        elif arg == '-ns':
            arguments["type"] = "name-server"
        else:
            if arguments.get("server-name", None) == None:
                arguments["server-name"] = arg[1:]
            else:
                arguments["domain-name"] = arg

    print(arguments)

    dns = DNSPackets()
    request = dns.encode(arguments)
    print(request)
    socket = Socket()

    socket.connect(arguments["server-name"], arguments.get("port", 53))
    tries = 0
    while tries < arguments.get("max-retries", 3):
        tries += 1
        socket.mysend(request)
