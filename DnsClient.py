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

        print(qname)
        print(qtype)
        print(qclass)
        print(header_bytes + question_bytes)
        return header_bytes + question_bytes

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
        MSGLEN = len(msg)
        while totalsent < MSGLEN:
            sent = self.sock.send(msg[totalsent:])
            if sent == 0:
                raise RuntimeError("socket connection broken")
            else:
                print("Sent " + str(sent) + " bytes.")
            totalsent = totalsent + sent

    def receive(self):
        chunks = []
        bytes_recd = 0
        MSGLEN = 60000
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
        self.sock.close()

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

    socket.connect(arguments["server-name"], int(arguments.get("port", 53)))
    socket.send(request)
    response = socket.receive()
    print(response)
    socket.close()
