"""
DNS lookup tool by Henry O'Brien (44341800)

Usage:
To perform a standard query:
    DNSLookup.py -s host [server]

To perform an inverse query:
    DNSLookup.py -i ip [server]
"""

import sys  # for reading cmd line args
import os  # to automate getting the default DNS server
import socket  # essential for sending the DNS request
import random  # for generating query IDs
import codecs  # for conversion to/from hexadecimal
import ipaddress  # for conversion of IP addresses
import multiprocessing  # used to handle timeouts
from enum import Enum

DNS_IP = "8.8.8.8"  # the deafult DNS IP
DNS_PORT = 53  # DNS port is always 53

POINTER_VAL = 49152  # minimum value for a name pointer
BYTE = 2  # size of a byte
WORD = 4  # size of a word
DWORD = 8  # size of two words


class Opcode(Enum):
    """Represents the Opcode of the DNS header"""
    QUERY = 0
    IQUERY = 1
    STATUS = 2


class QType(Enum):
    """Represents the type of a DNS question
    There is room to extend this enum for other types"""
    A = 1
    CNAME = 5
    SOA = 6
    MX = 15
    AAAA = 28
    PTR = 12


class QClass(Enum):
    """Represents the class of a DNS question
    There is room to extend this enum for other classes"""
    IN = 1


class Error(Enum):
    """Represents a DNS error code"""
    NONE = 0
    FORMAT = 1
    SERVER = 2
    NAME = 3
    IMPL = 4
    REFUSED = 5

# DNS error code meanings
ERROR_MSGS = {
    Error.FORMAT: "A format error was received. Please check your input and try again.",
    Error.SERVER: "A server failure occured. Please try again later.",
    Error.NAME: "Given name could not be resolved by the DNS server. Please check your input and try again.",
    Error.IMPL: "The attempted lookup is not supported by the DNS server.",
    Error.REFUSED: "The connection was refused. Please try again later."
}


class Direction(Enum):
    """Represents the direction a DNS query is travelling in"""
    QUERY = 0
    RESPONSE = 1


class ResponseError(Exception):
    """Thrown when a non-0 response code is received"""
    def __init__(self, errno):
        super().__init__()
        self._errno = errno

    def __str__(self):
        return ERROR_MSGS[self._errno]


class Header:
    """Class representing the header section of a DNS query"""

    def __init__(self, m_id=None, qr=Direction.QUERY, opcode=Opcode.QUERY, aa=0, tc=0, rd=1, ra=0, r_code=Error.NONE,
                 qd_count=1, an_count=0, ns_count=0, ar_count=0):
        if m_id is None:
            self._id = self.gen_id()
        else:
            self._id = m_id

        self._qr = qr
        self._opcode = opcode
        self._aa = int(aa)
        self._tc = int(tc)
        self._rd = int(rd)
        self._ra = int(ra)
        self._r_code = r_code
        self._qd_count = qd_count
        self._an_count = an_count
        self._ns_count = ns_count
        self._ar_count = ar_count

    @staticmethod
    def gen_id():
        """(str) Generates a random ID, in hex format"""
        return "{:04x}".format(random.randint(0, int(0xFFFF)))

    def gen_flags(self):
        """(str) Generates the hexadecimal representation of this header's flags"""
        return bin_to_hex(f"{self._qr.value}{int_to_bin(self._opcode.value, 4)}{self._aa}{self._tc}{self._rd}"
                          f"{self._ra}000{int_to_bin(self._r_code.value, 4)}")

    def encode(self):
        """(str) Generates the hexadecimal representation of this header"""
        return f"{self._id}{self.gen_flags()}{int_to_hex(self._qd_count, WORD)}{int_to_hex(self._an_count, WORD)}" \
               f"{int_to_hex(self._ns_count, WORD)}{int_to_hex(self._ar_count, WORD)}"

    def get_resp_code(self):
        """(Error) Returns the response code of the DNS request"""
        return self._r_code

    def get_question_count(self):
        """(int) Returns the number of questions in the DNS request"""
        return self._qd_count

    def get_answer_count(self):
        """(int) Returns the number of answers in the DNS request"""
        return self._an_count

    def get_nameserver_count(self):
        """(int) Returns the number of nameservers in the DNS request"""
        return self._ns_count

    @staticmethod
    def decode(data, orig):
        """Decodes a raw DNS request into a header

        Params:
            data (str) : the raw data to decode
            orig (str) : a copy of the raw data

        Returns:
            header (Header) : The decoded header
            data (str) : The header with the data removed
        """
        m_id = data[:WORD]
        data = data[WORD:]
        flags = hex_to_bin(data[:WORD])
        data = data[WORD:]
        questions = int(data[:WORD], 16)
        data = data[WORD:]
        answers = int(data[:WORD], 16)
        data = data[WORD:]
        auth = int(data[:WORD], 16)
        data = data[WORD:]
        addit = int(data[:WORD], 16)
        data = data[WORD:]
        new = Header(m_id, search_enum(Direction, int(flags[0])), search_enum(Opcode, int(flags[1:5], 2)),
                     int(flags[5]), int(flags[6]), int(flags[7]), int(flags[8]),
                     search_enum(Error, int(flags[12:16], 2)), questions, answers, auth, addit)
        return new, data


class Question:
    """Class representing the question section of a DNS query"""

    def __init__(self, name, q_type=QType.A, q_class=QClass.IN):
        self._name = name
        self._type = q_type
        self._class = q_class

    def gen_name(self):
        """(str) Generates the hexadecimal representation of this question's name"""
        result = ""
        labels = self._name.split(".")
        for lbl in labels:
            result += int_to_hex(len(lbl), 2)
            result += str_to_hex(lbl)
        return result + int_to_hex(0, 2)

    def encode(self):
        """(str) Generates the hexadecimal representation of this question"""
        return f"{self.gen_name()}{int_to_hex(self._type.value, WORD)}{int_to_hex(self._class.value, WORD)}"

    @staticmethod
    def decode(data, orig):
        """Decodes a raw DNS request into a question

        Params:
            data (str) : the data to decode, with the header removed
            orig (str) : the full data, including the header

        Returns:
            question (Question) : the decoded question
            data (str) : the data with the question removed
        """
        name, data = read_name(data, orig)
        q_type = search_enum(QType, int(data[:WORD], 16))
        data = data[WORD:]
        q_class = search_enum(QClass, int(data[:WORD], 16))
        data = data[WORD:]
        return Question(name, q_type, q_class), data


class Answer:
    """Class representing the answer section of a DNS query"""

    def __init__(self, name="", rr_type=QType.A, rr_class=QClass.IN, ttl=0, data=""):
        self._name = name
        self._type = rr_type
        self._class = rr_class
        self._ttl = ttl
        self._data = data

    def get_name(self):
        """(str) Returns the host name"""
        return self._name

    def get_type(self):
        """(QType) Returns the answer type"""
        return self._type

    def get_class(self):
        """(QClass) Returns the answer class"""
        return self._class

    def get_ttl(self):
        """(int) Returns the time to live of the answer"""
        return self._ttl

    def get_ipv4(self):
        """(str) Returns the IPv4 address if this answer is of type A, otherwise None"""
        if self._type == QType.A:
            return self._data

    def get_ipv6(self):
        """(str) Returns the IPv6 address if this answer is of type AAAA, otherwise None"""
        if self._type == QType.AAAA:
            return self._data

    def get_cname(self):
        """(str) Returns the canonical host name if this answer is of type CNAME, otherwise None"""
        if self._type == QType.CNAME:
            return self._data

    def get_mail_serv(self):
        """(str) Returns the host name of the mail server if this answer is of type MX, otherwise None"""
        if self._type == QType.MX:
            return self._data

    def get_domain_name(self):
        if self._type == QType.PTR:
            return self._data

    @staticmethod
    def read_data(data, orig, type_):
        if type_ == QType.A:
            return str(ipaddress.IPv4Address(hex_to_bytes(data)))
        elif type_ == QType.AAAA:
            return str(ipaddress.IPv6Address(hex_to_bytes(data)))
        elif type_ == QType.CNAME:
            result, _ = read_name(data, orig)
            return result
        elif type_ == QType.MX:
            result, _ = read_name(data[4:], orig)
            return result
        elif type_ == QType.PTR:
            result, _ = read_name(data, orig)
            return result
        return None

    @staticmethod
    def decode(data, orig):
        name, data = read_name(data, orig)
        type_ = search_enum(QType, int(data[:WORD], 16))
        data = data[WORD:]
        class_ = search_enum(QClass, int(data[:WORD], 16))
        data = data[WORD:]
        ttl = int(data[:DWORD], 16)
        data = data[DWORD:]
        r_len = int(data[:WORD], 16)
        data = data[WORD:]
        return Answer(name, type_, class_, ttl, data=Answer.read_data(data[:r_len*2], orig, type_)), data[r_len*2:]


class AuthNameserver(Answer):

    def __init__(self, name="", rr_type=QType.SOA, rr_class=QClass.IN, ttl=0, **kwargs):
        super().__init__(name, rr_type, rr_class, ttl, "")
        self._nameserver = kwargs["nameserver"]
        self._mailbox = kwargs["mailbox"]
        self._serial_no = kwargs["sno"]
        self._refresh_int = kwargs["ref_int"]
        self._retry_int = kwargs["ret_int"]
        self._expire_lim = kwargs["exp_lim"]
        self._min_ttl = kwargs["min_ttl"]

    def get_nameserver(self):
        """(str) Returns the nameserver as a string"""
        return self._nameserver

    @staticmethod
    def read_data(data, orig, type_):
        if type_ == QType.SOA:
            nameserver, data = read_name(data, orig)
            mailbox, data = read_name(data, orig)
            sno = data[:DWORD]
            data = data[DWORD:]
            ref_int = data[:DWORD]
            data = data[DWORD:]
            ret_int = data[:DWORD]
            data = data[DWORD:]
            exp_lim = data[:DWORD]
            data = data[DWORD:]
            min_ttl = data[:DWORD]
            data = data[DWORD:]
            return {"nameserver": nameserver, "mailbox": mailbox, "sno": int(sno, 16), "ref_int": int(ref_int, 16),
                    "ret_int": int(ret_int, 16), "exp_lim": int(exp_lim, 16), "min_ttl": int(min_ttl, 16)}

    @staticmethod
    def decode(data, orig):
        name, data = read_name(data, orig)
        type_ = search_enum(QType, int(data[:WORD], 16))
        data = data[WORD:]
        class_ = search_enum(QClass, int(data[:WORD], 16))
        data = data[WORD:]
        ttl = int(data[:DWORD], 16)
        data = data[DWORD:]
        r_len = int(data[:WORD], 16)
        data = data[WORD:]
        return AuthNameserver(name, type_, class_, ttl, **AuthNameserver.read_data(data[:r_len * 2], orig, type_)), \
               data[r_len * 2:]


def int_to_hex(num, length):
    """Converts an integer to a hexadecimal string with the given length

    Params:
        num (int) : the number to convert
        length (int) : the string length of the output

    Returns: (str) the hexadecimal representation of the given integer
    """
    return "{:x}".format(num).zfill(length)


def int_to_bin(num, length):
    """Converts an integer to a binary string with the given length

    Params:
        num (int) : the number to convert
        length (int) : the string length of the output

    Returns: (str) the binary representation of the given integer
    """
    return "{:b}".format(num).zfill(length)


def hex_to_bytes(hexa):
    """Converts a hexadecimal string to bytes

    Params:
        hexa (str) : the hex string to convert

    Returns: (bytes) the bytes representation of that hex number
    """
    return codecs.decode(hexa, "hex")


def bytes_to_hex(byte_str):
    """Converts a series of bytes to a hexadecimal string

    Params:
        byte_str (str) : the series of bytes to convert

    Returns: (str) the hexadecimal representation of the bytes
    """
    result = ""
    for i in byte_str:
        result += int_to_hex(i, 2)
    return result


def str_to_hex(string):
    """Converts a string to a hexadecimal string

    Params:
        string (str) : the string to convert

    Returns: (str) the hexadecimal representation of that string
    """
    return string.encode().hex()


def bin_to_hex(bin_str):
    """Converts a binary string to a hexadecimal string

    Params:
        bin_str (str) : the binary string to convert

    Returns: (str) the hexadecimal representation of that string
    """
    hex_str = ""
    for i in range(0, len(bin_str), 4):
        binr = bin_str[i:i+4]
        hex_str += "{:01x}".format(int(binr, 2))
    return hex_str


def hex_to_bin(hex_str):
    """Converts a hexadecimal string to a binary string

    Params:
        hex_str (str) : the hex string to convert

    Returns: (str) the binary representation of that string
    """
    bin_str = ""
    for i in hex_str:
        bin_str += bin(int(i, 16))[2:].zfill(4)
    return bin_str


def search_enum(enum_class, src):
    """Returns the enum value of a numerical value

    Params:
        enum_class (Class) : the exact type of the output
        src (int) : the numerical value to get the enum representation of

    Returns: (Enum) the enum representation of src
    """
    for obj in enum_class:
        if obj.value == src:
            return obj


def read_name(data, orig):
    """Reads a name from a hex string

    Params:
        data (str) : the hex string, starting at the name to read
        orig (str) : the entire hex string

    Returns: (str) : the decoded name
    """
    name = ""
    counter = -1
    size = -1
    while True:
        next_byte = data[:2]
        if next_byte == int_to_hex(0, 2):
            return name, data[2:]
        elif int(data[:4], 16) > POINTER_VAL:
            if counter == size and counter != -1:
                name += "."
            loc = (int(data[:4], 16) - POINTER_VAL)*2
            nxt, _ = read_name(orig[loc:], orig)
            name += nxt
            return name, data[4:]

        if counter == size:
            if counter != -1:
                name += "."
            size = int(next_byte, 16)
            counter = -1
        else:
            name += hex_to_bytes(next_byte).decode("ascii")

        data = data[2:]
        counter += 1


def parse_response(sock):
    """Decodes a response into a series of objects

    Params:
        sock (socket) : the socket to read from

    Returns:
        answers (list<Answer>) : a list of answers in the response - used for standard queries
        nameservers (list<AuthNameserver>) : a list of nameservers in the response - used for inverse queries
    """
    resp_bytes, addr = sock.recvfrom(2048)
    reply = bytes_to_hex(resp_bytes)
    orig = reply

    header, reply = Header.decode(reply, orig)
    code = header.get_resp_code()
    if code != Error.NONE:
        raise ResponseError(code)

    for i in range(header.get_question_count()):
        question, reply = Question.decode(reply, orig)

    answers = []
    for i in range(header.get_answer_count()):
        ans, reply = Answer.decode(reply, orig)
        answers.append(ans)

    nameservers = []
    for i in range(header.get_nameserver_count()):
        ans, reply = AuthNameserver.decode(reply, orig)
        nameservers.append(ans)

    return answers, nameservers


def query_ip(sock, dns, url, ipv):
    if ipv == 4:
        header = Header()
        question = Question(url, q_type=QType.A)
    elif ipv == 6:
        header = Header()
        question = Question(url, q_type=QType.AAAA)
    else:
        return []
    msg = header.encode() + question.encode()
    sock.sendto(hex_to_bytes(msg), (dns, DNS_PORT))

    resp, _ = parse_response(sock)

    return [r for r in resp if r.get_type() in (QType.A, QType.AAAA, QType.CNAME)]


def query_mail(sock, dns, url):
    header = Header()
    question = Question(url, q_type=QType.MX)
    msg = header.encode() + question.encode()
    sock.sendto(hex_to_bytes(msg), (dns, DNS_PORT))

    parsed, _ = parse_response(sock)
    result = []
    for ans in parsed:
        if ans.get_type() == QType.MX:
            server_name = ans.get_mail_serv()
            v4 = query_ip(sock, dns, server_name, 4)
            v6 = query_ip(sock, dns, server_name, 6)
            result.append((ans.get_name(), server_name, v4, v6))
    return result


def query_helper(repl, res):
    for ans in repl:
        if res.get(ans.get_name()) is None:
            res[ans.get_name()] = {"ipv4": [], "ipv6": [], "mail": []}
        if ans.get_ipv4() is not None:
            res[ans.get_name()]["ipv4"].append(ans.get_ipv4())
        if ans.get_ipv6() is not None:
            res[ans.get_name()]["ipv6"].append(ans.get_ipv6())
        if ans.get_cname() is not None:
            res[ans.get_name()]["cname"] = ans.get_cname()


def inv_query(sock, dns, url):
    inv_url = ".".join(url.split(".")[::-1]) + ".in-addr.arpa"
    header = Header()
    question = Question(inv_url, q_type=QType.PTR)
    msg = header.encode() + question.encode()
    sock.sendto(hex_to_bytes(msg), (dns, DNS_PORT))

    resp, _ = parse_response(sock)
    return [r.get_domain_name() for r in resp if r.get_type() == QType.PTR]


def exec_query(sock, dns, url):
    ipv4 = query_ip(sock, dns, url, 4)
    ipv6 = query_ip(sock, dns, url, 6)
    mail = query_mail(sock, dns, url)

    res = {"hosts": {}, "mail": {}}

    query_helper(ipv4, res["hosts"])
    query_helper(ipv6, res["hosts"])

    for host, server, v4, v6 in mail:
        query_helper(v4, res["mail"])
        query_helper(v6, res["mail"])
        res["hosts"][host]["mail"].append(server)

    return res


def query(args):
    sock = args["sock"]
    dns = args["dns"]
    url = args["url"]
    inverse = args["inv"]

    try:
        if inverse:
            args["result"] = inv_query(sock, dns, url)
        else:
            args["result"] = exec_query(sock, dns, url)
    except ResponseError as e:
        args["err"] = str(e)
    except:
        args["err"] = "Oops! Something went wrong. Please check your input and try again."


def connect_and_query(url, dns, inverse=False):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        manager = multiprocessing.Manager()
        p_data = manager.dict()
        p_data["sock"] = sock
        p_data["url"] = url
        p_data["dns"] = dns
        p_data["inv"] = inverse
        p = multiprocessing.Process(target=query, args=(p_data,))
        p.start()
        p.join(10)  # wait 10 secs
        if p.is_alive():
            p.terminate()
            p.join()
            p_data["err"] = "Request timed out. Please check the server ip and your internet connection " \
                            "and try again."
    return p_data


def get_default_dns():
    """This is used to get the DNS server of the local computer
    Used by the GUI to set a default server

    nslookup is not used anywhere else in the program
    """
    stream = os.popen("nslookup localhost")
    return stream.readline().split(":")[1].strip()


def print_result(inp, res):
    if res is None:
        print("Oops, something went wrong. Please check your input and try again. Received None from processing.")
        return
    if isinstance(res, dict):
        print(f"Standard DNS lookup for host {inp}")
        for i in [res["hosts"], res["mail"]]:
            if i == res["mail"]:
                if len(i) == 0:
                    print("\nNo mail servers associated with this host")
                else:
                    print("\nMail servers:", end="")
            else:
                print("\nHosts:", end="")
            for h in i:
                print("\n\t" + h)
                if i[h].get('cname') is not None:
                    print(f"\t\tCanonical name: {i[h].get('cname')}")
                else:
                    ipv4s = ', '.join(i[h].get('ipv4'))
                    ipv6s = ', '.join(i[h].get('ipv6'))
                    if ipv4s == "":
                        print("\t\tNo IPv4 addrs available")
                    else:
                        print("\t\tIPv4 addr(s): " + ipv4s)
                    if ipv6s == "":
                        print("\t\tNo IPv6 addrs available")
                    else:
                        print("\t\tIPv6 addr(s): " + ipv6s)
    else:
        print(f"Reverse DNS lookup for IP {inp}\n")
        if len(res) == 0:
            print("No hosts found for the given IP\n")
        else:
            print("Host(s) associated with this IP are:")
            for i in res:
                print(f"\t{i}")


def main(argc, argv):
    if argc < 3 or argc > 5:
        print("Usage: DNSLookup.py (-s | -i) host [server]")
        return
    if argv[1] == "-i":
        inverse = True
    elif argv[1] == "-s":
        inverse = False
    else:
        print("Usage: DNSLookup.py (-s | -i) host [server]")
        return
    url = argv[2]
    if argc >= 4:
        if argv[3] == "-d":
            dns = DNS_IP
        else:
            dns = argv[3]
    else:
        dns = DNS_IP

    result = connect_and_query(url, dns, inverse)
    result.pop('sock')  # we certainly don't want this in the answer
    if argc == 5 and argv[4] == "-r":
        print(result)
        return
    elif argc == 5:
        print("Usage: DNSLookup.py (-s | -i) host [server]")
        return
    if result.get("err") is not None:
        print(result.get("err"))
    else:
        print_result(url, result.get("result"))


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
