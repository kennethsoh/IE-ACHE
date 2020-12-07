import time
import hashlib
import random
import logging
import socket
import re, uuid
import base64
import os, random, struct
import subprocess
import sys
import asn1tools
from collections import namedtuple
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from optparse import *
import sys
from ipaddress import ip_address, IPv6Address
import select

# THE PURPOSE OF THIS FILE IS TO HANDLE USER INPUT AND REQUEST FOR DRAGONFLY KEY EXCHANGE TO BE COMPLETED

asn1_file = asn1tools.compile_files("declaration.asn")

def validateIP(IP: str) -> str:
    try:
        return "IPv6" if type(ip_address(IP)) is IPv6Address else "IPv4"
    except ValueError:
        return "Invalid"

def generateMd5(file_name):
    hash_md5 = hashlib.md5()
    with open(file_name, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
        return hash_md5.hexdigest()

    
def dragonfly():
    # Request Keygen to initiate Dragonfly SAE
    print("Starting Dragonfly Key Exchange ")

    # Wait
    print('Executing dragonfly code for Private key')
    time.sleep(1)

    #Executing Dragonfly code for private key
    subprocess.run('./dragonfly_private_Output.py')
    MD5_PrivKey = generateMd5("secret.key")
    print ("MD5 of private key:", MD5_PrivKey)

    print("Waiting for dragonfly to finish...")

    sock_message.bind(own_address_kg)
    sock_message.listen(1)
    connection, output_address = sock_message.accept()
    with connection:
        print ("Connecting from", output_address)
        message_encode = connection.recv(1024)
        message = message_encode.decode()
        print(message)
    if (message == "finished"):
        sock_message.close()
        handshake("client1", "client2", "client3", "client4", "opcode1", "opcode2", "opcode3", "postfix")
    else:
        None


    #while True:
    #   confirm_code = input("Has dragonfly occured between client / output / cloud? (yes/no)")
    #   if str(confirm_code).lower() == "yes":
    #       handshake("client1", "client2", "client3", "opcode1", "opcode2", "postfix")
    #       break
    #   else:
    #       None
    

###############################################33
# Postfix conversion
class Stack:
    def __init__(self):
        self.items = []

    def isEmpty(self):
        return self.items == []

    def push(self, item):
        self.items.append(item)

    def pop(self):
        return self.items.pop()

    def peek(self):
        return self.items[self.size()-1]

    def size(self):
        return len(self.items)

class InfixConverter:
    def __init__(self):
        self.stack = Stack()
        self.precedence = {'+':1, '-':1, '*':2, '/':2, '^':3}

    def hasLessOrEqualPriority(self, a, b):
        if a not in self.precedence:
            return False
        if b not in self.precedence:
            return False
        return self.precedence[a] <= self.precedence[b]

    def isOperator(self, x):
        ops = ['+', '-', '/', '*']
        return x in ops

    def isOperand(self, ch):
        return ch.isalpha() or ch.isdigit()

    def isOpenParenthesis(self, ch):
        return ch == '('

    def isCloseParenthesis(self, ch):
        return ch == ')'

    def toPostfix(self, expr):
        expr = expr.replace(" ", "")
        self.stack = Stack()
        output = ''

        for c in expr:
            if self.isOperand(c):
                output += c
            else:
                if self.isOpenParenthesis(c):
                    self.stack.push(c)
                elif self.isCloseParenthesis(c):
                    operator = self.stack.pop()
                    while not self.isOpenParenthesis(operator):
                        output += operator
                        operator = self.stack.pop()
                else:
                    while (not self.stack.isEmpty()) and self.hasLessOrEqualPriority(c,self.stack.peek()):
                        output += self.stack.pop()
                    self.stack.push(c)

        while (not self.stack.isEmpty()):
            output += self.stack.pop()
        return output

    def convert(self, expr):
        print( '''
            Original expr is: {}
            Postfix is: {}
        '''.format(expr, self.toPostfix(expr)))





#############################################
logger = logging.getLogger('dragonfly')
logger.setLevel(logging.INFO)
# create file handler which logs even debug messages
fh = logging.FileHandler('dragonfly.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)
# add the handlers to logger
logger.addHandler(ch)
logger.addHandler(fh)


Point = namedtuple("Point", "x y")
# The point at infinity (origin for the group law).
O = 'Origin'

def lsb(x):
    binary = bin(x).lstrip('0b')
    return binary[0]

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def tonelli_shanks(n, p):
    """
    # https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#Python
    """
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

class Curve():
    """
    Mathematical operations on a Elliptic Curve.

    A lot of code taken from:
    https://stackoverflow.com/questions/31074172/elliptic-curve-point-addition-over-a-finite-field-in-python
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def curve_equation(self, x):
        """
        We currently use the elliptic curve
        NIST P-384
        """
        return (pow(x, 3) + (self.a * x) + self.b) % self.p

    def is_quadratic_residue(self, x):
        """
        https://en.wikipedia.org/wiki/Euler%27s_criterion
        Computes Legendre Symbol.
        """
        return pow(x, (self.p-1) // 2, self.p) == 1

    def valid(self, P):
        """
        Determine whether we have a valid representation of a point
        on our curve.  We assume that the x and y coordinates
        are always reduced modulo p, so that we can compare
        two points for equality with a simple ==.
        """
        if P == O:
            return True
        else:
            return (
                    (P.y**2 - (P.x**3 + self.a*P.x + self.b)) % self.p == 0 and
                    0 <= P.x < self.p and 0 <= P.y < self.p)

    def inv_mod_p(self, x):
        """
        Compute an inverse for x modulo p, assuming that x
        is not divisible by p.
        """
        if x % self.p == 0:
            raise ZeroDivisionError("Impossible inverse")
        return pow(x, self.p-2, self.p)

    def ec_inv(self, P):
        """
        Inverse of the point P on the elliptic curve y^2 = x^3 + ax + b.
        """
        if P == O:
            return P
        return Point(P.x, (-P.y) % self.p)

    def ec_add(self, P, Q):
        """
        Sum of the points P and Q on the elliptic curve y^2 = x^3 + ax + b.
        https://stackoverflow.com/questions/31074172/elliptic-curve-point-addition-over-a-finite-field-in-python
        """
        if not (self.valid(P) and self.valid(Q)):
            raise ValueError("Invalid inputs")

        # Deal with the special cases where either P, Q, or P + Q is
        # the origin.
        if P == O:
            result = Q
        elif Q == O:
            result = P
        elif Q == self.ec_inv(P):
            result = O
        else:
            # Cases not involving the origin.
            if P == Q:
                dydx = (3 * P.x**2 + self.a) * self.inv_mod_p(2 * P.y)
            else:
                dydx = (Q.y - P.y) * self.inv_mod_p(Q.x - P.x)
            x = (dydx**2 - P.x - Q.x) % self.p
            y = (dydx * (P.x - x) - P.y) % self.p
            result = Point(x, y)

        # The above computations *should* have given us another point
        # on the curve.
        assert self.valid(result)
        return result

    def double_add_algorithm(self, scalar, P):
        """
        Double-and-Add Algorithm for Point Multiplication
        Input: A scalar in the range 0-p and a point on the elliptic curve P
        https://stackoverflow.com/questions/31074172/elliptic-curve-point-addition-over-a-finite-field-in-python
        """
        assert self.valid(P)

        b = bin(scalar).lstrip('0b')
        T = P
        for i in b[1:]:
            T = self.ec_add(T, T)
            if i == '1':
                T = self.ec_add(T, P)

        assert self.valid(T)
        return T

class Peer:
    """
    Implements https://wlan1nde.wordpress.com/2018/09/14/wpa3-improving-your-wlan-security/
    Take a ECC curve from here: https://safecurves.cr.yp.to/

    Example: NIST P-384
    y^2 = x^3-3x+27580193559959705877849011840389048093056905856361568521428707301988689241309860865136260764883745107765439761230575
    modulo p = 2^384 - 2^128 - 2^96 + 2^32 - 1
    2000 NIST; also in SEC 2 and NSA Suite B

    See here: https://www.rfc-editor.org/rfc/rfc5639.txt

Curve-ID: brainpoolP256r1
      p =
      A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
      A =
      7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
      B =
      26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6
      x =
      8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
      y =
      547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997
      q =
      A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
      h = 1
    """

    def __init__(self, password, mac_address, name):
        self.name = name
        self.password = password
        self.mac_address = mac_address

        # Try out Curve-ID: brainpoolP256t1
        self.p = int('A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377', 16)
        self.a = int('7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9', 16)
        self.b = int('26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6', 16)
        self.q = int('A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7', 16)
        self.curve = Curve(self.a, self.b, self.p)

        # A toy curve
        # self.a, self.b, self.p = 2, 2, 17
        # self.q = 19
        # self.curve = Curve(self.a, self.b, self.p)

    def initiate(self, other_mac, k=40):
        """
        See algorithm in https://tools.ietf.org/html/rfc7664
        in section 3.2.1
        """
        self.other_mac = other_mac
        found = 0
        num_valid_points = 0
        counter = 1
        n = self.p.bit_length() + 64

        while counter <= k:
            base = self.compute_hashed_password(counter)
            temp = self.key_derivation_function(n, base, 'Dragonfly Hunting And Pecking')
            seed = (temp % (self.p - 1)) + 1
            val = self.curve.curve_equation(seed)
            if self.curve.is_quadratic_residue(val):
                if num_valid_points < 5:
                    x = seed
                    save = base
                    found = 1
                    num_valid_points += 1
                    logger.debug('Got point after {} iterations'.format(counter))

            counter = counter + 1

        if found == 0:
            logger.error('No valid point found after {} iterations'.format(k))
        elif found == 1:
            # https://crypto.stackexchange.com/questions/6777/how-to-calculate-y-value-from-yy-mod-prime-efficiently
            # https://rosettacode.org/wiki/Tonelli-Shanks_algorithm
            y = tonelli_shanks(self.curve.curve_equation(x), self.p)

            PE = Point(x, y)

            # check valid point
            assert self.curve.curve_equation(x) == pow(y, 2, self.p)

            logger.info('[{}] Using {}-th valid Point={}'.format(self.name, num_valid_points, PE))
            logger.info('[{}] Point is on curve: {}'.format(self.name, self.curve.valid(PE)))

            self.PE = PE
            assert self.curve.valid(self.PE)

    def commit_exchange(self):
        """
        This is basically Diffie Hellman Key Exchange (or in our case ECCDH)

        In the Commit Exchange, both sides commit to a single guess of the
        password.  The peers generate a scalar and an element, exchange them
        with each other, and process the other's scalar and element to
        generate a common and shared secret.

        If we go back to elliptic curves over the real numbers, there is a nice geometric
        interpretation for the ECDLP: given a starting point P, we compute 2P, 3P, . . .,
        d P = T , effectively hopping back and forth on the elliptic curve. We then publish
        the starting point P (a public parameter) and the final point T (the public key). In
        order to break the cryptosystem, an attacker has to figure out how often we “jumped”
        on the elliptic curve. The number of hops is the secret d, the private key.
        """
        # seed the PBG before picking a new random number
        # random.seed(time.process_time())

        # None or no argument seeds from current time or from an operating
        # system specific randomness source if available.
        random.seed()

        # Otherwise, each party chooses two random numbers, private and mask
        self.private = random.randrange(1, self.p)
        self.mask = random.randrange(1, self.p)

        logger.debug('[{}] private={}'.format(self.name, self.private))
        logger.debug('[{}] mask={}'.format(self.name, self.mask))

        # These two secrets and the Password Element are then used to construct
        # the scalar and element:

        # what is q?
        # o  A point, G, on the elliptic curve, which serves as a generator for
        #    the ECC group.  G is chosen such that its order, with respect to
        #    elliptic curve addition, is a sufficiently large prime.
        #
        # o  A prime, q, which is the order of G, and thus is also the size of
        #    the cryptographic subgroup that is generated by G.

        # https://math.stackexchange.com/questions/331329/is-it-possible-to-compute-order-of-a-point-over-elliptic-curve
        # In the elliptic Curve cryptography, it is said that the order of base point
        # should be a prime number, and order of a point P is defined as k, where kP=O.

        # Theorem 9.2.1 The points on an elliptic curve together with O
        # have cyclic subgroups. Under certain conditions all points on an
        # elliptic curve form a cyclic group.
        # For this specific curve the group order is a prime and, according to Theo-
        # rem 8.2.4, every element is primitive.

        # Question: What is the order of our PE?
        # the order must be p, since p is a prime

        self.scalar = (self.private + self.mask) % self.q

        # If the scalar is less than two (2), the private and mask MUST be
        # thrown away and new values generated.  Once a valid scalar and
        # Element are generated, the mask is no longer needed and MUST be
        # irretrievably destroyed.
        if self.scalar < 2:
            raise ValueError('Scalar is {}, regenerating...'.format(self.scalar))

        P = self.curve.double_add_algorithm(self.mask, self.PE)

        # get the inverse of res
        # −P = (x_p , p − y_p ).
        self.element = self.curve.ec_inv(P)

        assert self.curve.valid(self.element)

        # The peers exchange their scalar and Element and check the peer's
        # scalar and Element, deemed peer-scalar and Peer-Element.  If the peer
        # has sent an identical scalar and Element -- i.e., if scalar equals
        # peer-scalar and Element equals Peer-Element -- it is sign of a
        # reflection attack, and the exchange MUST be aborted.  If the values
        # differ, peer-scalar and Peer-Element must be validated.

        logger.info('[{}] Sending scalar and element to the Peer!'.format(self.name))
        logger.info('[{}] Scalar={}'.format(self.name, self.scalar))
        logger.info('[{}] Element={}'.format(self.name, self.element))

        return self.scalar, self.element

    def compute_shared_secret(self, peer_element, peer_scalar, peer_mac):
        """
        ss = F(scalar-op(private,
                                         element-op(peer-Element,
                                                                scalar-op(peer-scalar, PE))))

        AP1: K = private(AP1) • (scal(AP2) • P(x, y) ◊ new_point(AP2))
                   = private(AP1) • private(AP2) • P(x, y)
        AP2: K = private(AP2) • (scal(AP1) • P(x, y) ◊ new_point(AP1))
                   = private(AP2) • private(AP1) • P(x, y)

        A shared secret element is computed using one’s rand and
        the other peer’s element and scalar:
        Alice: K = rand A • (scal B • PW + elemB )
        Bob: K = rand B • (scal A • PW + elemA )

        Since scal(APx) • P(x, y) is another point, the scalar multiplied point
        of e.g. scal(AP1) • P(x, y) is added to the new_point(AP2) and afterwards
        multiplied by private(AP1).
        """
        self.peer_element = peer_element
        self.peer_scalar = peer_scalar
        self.peer_mac = peer_mac

        assert self.curve.valid(self.peer_element)

        # If both the peer-scalar and Peer-Element are
        # valid, they are used with the Password Element to derive a shared
        # secret, ss:

        Z = self.curve.double_add_algorithm(self.peer_scalar, self.PE)
        ZZ = self.curve.ec_add(self.peer_element, Z)
        K = self.curve.double_add_algorithm(self.private, ZZ)

        self.k = K[0]

        logger.info('[{}] Shared Secret ss={}'.format(self.name, self.k))

        own_message = '{}{}{}{}{}{}'.format(self.k , self.scalar , self.peer_scalar , self.element[0] , self.peer_element[0] , self.mac_address).encode()

        H = hashlib.sha256()
        H.update(own_message)
        self.token = H.hexdigest()

        return self.token

    def confirm_exchange(self, peer_token):
        """
                In the Confirm Exchange, both sides confirm that they derived the
                same secret, and therefore, are in possession of the same password.
        """
        peer_message = '{}{}{}{}{}{}'.format(self.k , self.peer_scalar , self.scalar , self.peer_element[0] , self.element[0] , self.peer_mac).encode()
        H = hashlib.sha256()
        H.update(peer_message)
        self.peer_token_computed = H.hexdigest()

        logger.info('[{}] Computed Token from Peer={}'.format(self.name, self.peer_token_computed))
        logger.info('[{}] Received Token from Peer={}'.format(self.name, peer_token))

        # Pairwise Master Key” (PMK)
        # compute PMK = H(k | scal(AP1) + scal(AP2) mod q)
        pmk_message = '{}{}'.format(self.k, (self.scalar + self.peer_scalar) % self.q).encode()
        #H = hashlib.sha256()
        #H.update(pmk_message)
        self.PMK = hashlib.sha256(pmk_message).digest()

        logger.info('[{}] Pairwise Master Key(PMK)={}'.format(self.name, self.PMK))
        return self.PMK

    def key_derivation_function(self, n, base, seed):
        """
        B.5.1 Per-Message Secret Number Generation Using Extra Random Bits

        Key derivation function from Section B.5.1 of [FIPS186-4]

        The key derivation function, KDF, is used to produce a
        bitstream whose length is equal to the length of the prime from the
        group's domain parameter set plus the constant sixty-four (64) to
        derive a temporary value, and the temporary value is modularly
        reduced to produce a seed.
        """
        combined_seed = '{}{}'.format(base, seed).encode()

        # base and seed concatenated are the input to the RGB
        random.seed(combined_seed)

        # Obtain a string of N+64 returned_bits from an RBG with a security strength of
        # requested_security_strength or more.

        randbits = random.getrandbits(n)
        binary_repr = format(randbits, '0{}b'.format(n))

        assert len(binary_repr) == n

        logger.debug('Rand={}'.format(binary_repr))

        # Convert returned_bits to the non-negative integer c (see Appendix C.2.1).
        C = 0
        for i in range(n):
            if int(binary_repr[i]) == 1:
                C += pow(2, n-i)

        logger.debug('C={}'.format(C))

        #k = (C % (n - 1)) + 1

        k = C

        logger.debug('k={}'.format(k))

        return k

    def compute_hashed_password(self, counter):
        maxm = max(self.mac_address, self.other_mac)
        minm = min(self.mac_address, self.other_mac)
        message = '{}{}{}{}'.format(maxm, minm, self.password, counter).encode()
        logger.debug('Message to hash is: {}'.format(message))
        H = hashlib.sha256()
        H.update(message)
        digest = H.digest()
        return digest

def encrypting(key, filename):
    chunksize = 64*1024
    outputFile = filename+".hacklab"
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                outfile.write(encryptor.encrypt(chunk))

    return outputFile

def handshake(CLIENT1, CLIENT2, CLIENT3, CLIENT4, OPCODE1, OPCODE2, OPCODE3, POSTFIX):
    #Own mac address
    own_mac = (':'.join(re.findall('..', '%012x' % uuid.getnode())))

    #Encode MAC address with BER
    own_mac_BER = asn1_file.encode('DataMac', {'data': own_mac})

    print (own_mac)
    ap = Peer('abc1238', own_mac, 'AP')

    logger.info('Attempting Dragonfly Key Exchange with cloud\n')
    logger.info('Starting hunting and pecking to derive PE...\n')
    
    own_ipaddr = "192.168.0.4"
    own_address = (own_ipaddr, 4381)
    own_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    own_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    own_sock.bind(own_address)
    own_sock.listen(1)
    connection, output_address = own_sock.accept()
    with connection:
        print ("Connecting from", output_address)
        raw_other_mac = connection.recv(1024)

        #decode BER and get MAC address
        other_decode_mac = asn1_file.decode('DataMac', raw_other_mac)
        other_mac = other_decode_mac.get('data')

        print ("Other MAC", other_mac)

        #Sending BER encoded
        connection.send(own_mac_BER)

        ap.initiate(other_mac)

        print()
        logger.info('Starting dragonfly commit exchange...\n')

        scalar_ap, element_ap = ap.commit_exchange()

        #encode scalar_ap / element_ap
        scalar_complete = ("\n".join([str(scalar_ap), str(element_ap)]))
        encoded = asn1_file.encode('DataScalarElement',{'data': scalar_complete})

        print('data send', scalar_complete)

        #Send BER encoded scalar / element ap to peer
        connection.sendall(encoded)
        print()

        logger.info('Computing shared secret...\n')

        #recevied BER encode scalar / element and decoded
        scalar_element_ap_encoded= connection.recv(1024)
        scalar_element_ap_decoded = asn1_file.decode('DataScalarElement', scalar_element_ap_encoded)
        scalar_element_ap = scalar_element_ap_decoded.get('data')

        print('scalar element received', scalar_element_ap)

        data = scalar_element_ap.split('\n')
        scalar_sta = data[0]
        element_sta = data[1]
        print ('scalar_sta recv:',scalar_sta)
        print()
        print ('element_sta recv:',element_sta)
        print ()
        namedtuple_element_sta = eval(element_sta)
        print(namedtuple_element_sta.y, namedtuple_element_sta.x)
        print ()
        print ()
        ap_token = ap.compute_shared_secret(namedtuple_element_sta, int(scalar_sta), other_mac)

        #Encode ap_token to be BER and send to peer
        apToken_encoded = asn1_file.encode('DataStaAp',{'data':ap_token})
        connection.send(apToken_encoded)

        print("ap_token data being send over", ap_token)
        
        print()
        logger.info('Confirm Exchange...\n')

        #Received BER encoded STA token and decode it
        staToken_encoded = connection.recv(1024)
        staToken_decoded = asn1_file.decode('DataStaAp', staToken_encoded)
        sta_token = staToken_decoded.get('data')

        print('received STA token', sta_token)

        PMK_Key = ap.confirm_exchange(sta_token)
        #print (PMK_Key)

        dragonfly_time = time.perf_counter()
        time_elapsed = round((dragonfly_time - start), 3)
        print('Total time elapsed for Dragonfly Key Exchange:', time_elapsed, 's')
        f = open('timings.txt', 'a')
        f.write('Total time elapsed for Dragonfly Key Exchange:')
        f.write(str(time_elapsed))
        f.write("")
        f.close

        # Start measuring final section of user input processing time
        usr_input_final_start = time.perf_counter()

        cl_ip = []
        cl_op = []

        ip_ber_dict = {}
        op_ber_dict = {}
        postfix_dict = {}

        # Write client1_ipaddr to client1 file
        c1 = open("client1", "w")
        c1.write(client1_ipaddr)
        c1.close()
        output_client1 = encrypting(PMK_Key, CLIENT1)
        c1 = open("client1.hacklab", "rb")
        client1_ipaddr_read = c1.read()
        cl_ip.append(client1_ipaddr_read)

        # Write client2_ipaddr to client2 file
        c2 = open("client2", "w")
        c2.write(client2_ipaddr)
        c2.close()
        output_client2 = encrypting(PMK_Key, CLIENT2)
        c2 = open("client2.hacklab", "rb")
        client2_ipaddr_read = c2.read()
        cl_ip.append(client2_ipaddr_read)

        if 'client3_ipaddr' in globals():
            # Write client3_ipaddr to client3 file
            c3 = open("client3", "w")
            c3.write(client3_ipaddr)
            c3.close()
            output_client3 = encrypting(PMK_Key, CLIENT3)
            c3 = open("client3.hacklab", "rb")
            client3_ipaddr_read = c3.read()
            cl_ip.append(client3_ipaddr_read)
        else:
            None

        if 'client4_ipaddr' in globals():
            # Write client4_ipaddr to client3 file
            c4 = open("client4", "w")
            c4.write(client4_ipaddr)
            c4.close()
            output_client4 = encrypting(PMK_Key, CLIENT4)
            c4 = open("client4.hacklab", "rb")
            client4_ipaddr_read = c4.read()
            cl_ip.append(client4_ipaddr_read)
        else:
            None

        # Write OPERATION 1 to operation file
        o1 = open("opcode1", "w")
        o1.write(OPERATION1)
        o1.close()
        output_operator1 = encrypting(PMK_Key, OPCODE1)
        o1 = open("opcode1.hacklab", "rb")
        operator1_read = o1.read()
        cl_op.append(operator1_read)
        o = open("operator.txt", "w")
        o.write(OPERATION1)
        o.close()
        
        if 'OPERATION2' in globals():
            # Write OPERATION 2 to operation file
            o2 = open("opcode2", "w")
            o2.write(OPERATION2)
            o2.close()
            output_operator2 = encrypting(PMK_Key, OPCODE2)
            o2 = open("opcode2.hacklab", "rb")
            operator2_read = o2.read()
            cl_op.append(operator2_read)
            o = open("operator.txt", "w")
            o.write(OPERATION2)
            o.close()
        else:
            None

        if 'OPERATION3' in globals():
            # Write OPERATION 3 to operation file
            o3 = open("opcode3", "w")
            o3.write(OPERATION3)
            o3.close()
            output_operator3 = encrypting(PMK_Key, OPCODE3)
            o3 = open("opcode3.hacklab", "rb")
            operator3_read = o3.read()
            cl_op.append(operator3_read)
            o = open("operator.txt", "w")
            o.write(OPERATION3)
            o.close()
        else:
            None

        # Write postfix_expr to postfix file
        p = open("postfix", "w")
        p.write(postfix_expr)
        p.close()
        output_postfix = encrypting(PMK_Key, POSTFIX)
        p = open("postfix.hacklab", "rb")
        postfix_read = p.read()
        postfix_dict['postfix'] = postfix_read
        

        usr_input_final_stop = time.perf_counter()
        usr_input_time_total = usr_input_final_stop - usr_input_final_start
        usr_input_time_total = round((usr_input_time_total + usr_input_time1), 3)
        f = open('timings.txt', 'a')
        f.write('Total time elapsed for user input processing: ')
        f.write(str(usr_input_time_total))
        f.write('')
        f.close
        print('Total time elapsed for user input processing: ', usr_input_time_total, 's')




        for i in range(len(cl_ip)):
            ip_ber_dict["ipaddress{0}".format(i+1)] = cl_ip[i]
        for i in range(len(cl_op)):
            op_ber_dict["operation{0}".format(i+1)] = cl_op[i]
        
        input_encoded = asn1_file.encode('DataUserInput',{'ipaddress':ip_ber_dict,'operation':op_ber_dict,'postfix':postfix_dict})

        print(input_encoded)
        print("LENGTH OF INPUT BER", len(input_encoded))

#####
        while True:
            #Send user input data to cloud
            connection.sendall(input_encoded)

            #Receive msg
            encoded_msg = connection.recv(1024)
            msg = encoded_msg.decode()

            #If success
            if (msg == "success"):
                #connection.shutdown(socket.SHUT_RDWR)
                #connection.close()
                break
            #If fails, resend
            else:
                continue
#####
        print("Sending your input to CLOUD\n")


    #own_ipaddr = "192.168.0.4"
    #own_address = (own_ipaddr, 4381)
    #own_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #own_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #own_sock.bind(own_address)
    #own_sock.listen(1)

#######
    connection, output_address = own_sock.accept()
    with connection:

    #Wait for CLOUD response#
    #Answer data size
        print("Waiting for CLOUD to return computed answer")
        with open ("answer.data", "wb") as a:
            print("answer.data file opened...\n")
            
            while True:
                try:
                    msg = connection.recv(1024)

                    ans_size_decoded = asn1_file.decode('DataAnsSize', msg)
                    ans_size = int(ans_size_decoded.get('data'))
                    print("Answer.data size", ans_size)

                    #Send success msg to cloud
                    msg = "success"
                    connection.send(msg.encode())

                    #Break out of while loop
                    break

                except:

                    #Print error msg
                    print(sys.exc_info()[0])

                    #Empty out error msg
                    read_con = [connection]
                    while True:
                        r, w, e = select.select(read_con, [], [], 0.0)
                        if len(r) == 0:
                            break
                        else:
                            for data in r:
                                data.recv(1024)

                    #send fail msg to output
                    msg = "fail"
                    connection.send(msg.encode())

                    #Testing phase
                    # buffer_size_t = int(input("size of buffer?"))
                    continue
            # time.sleep(5)
            gans_size = 0

            buffer_size = 1040
            # buffer_size = 50
            while True:
                try:
                    while True:
                        print ('Receiving data...\n')

                        #BER receiving data & decode
                        answer_data = connection.recv(buffer_size)

                        #TESTING phase
                        # buffer_size -= 10

                        print("Received length data from server", len(answer_data))
                        print(answer_data)
                        answer_data_decoded_dict = asn1_file.decode('DataAnswer', answer_data)
                        answer_data_decoded_raw = answer_data_decoded_dict.get('data')
                        
                        #Writing data
                        a.write(answer_data_decoded_raw)

                        #Send success message to cloud
                        msg = "success"
                        connection.send(msg.encode())

                        #Break occur if all data is received
                        print("gans size",gans_size)
                        
                        gans_size += len(answer_data_decoded_raw)
                        if gans_size >= ans_size:
                            print('Breaking from file write')
                            break

                except:
                    #Print error message
                    print("An error occured:", sys.exc_info()[0])

                    #empty out data from socket
                    read_con = [connection]
                    while True:
                        # own_sock.setblocking(0)
                        r, w, e = select.select(read_con, [], [], 0.0)
                        if len(r) == 0:
                            break
                        else:
                            for data in r:
                                data.recv(1024)

                    #TESTING phase
                    # buffer_size = int(input("size of buffer size?\n"))

                    #Send fail message to cloud
                    msg = "fail"
                    connection.send(msg.encode())
                    continue
                
                else:
                    #Breaking out of while loop
                    if gans_size >= ans_size:
                        break
                    # own_sock.shutdown(socket.SHUT_RDWR)
                    # own_sock.close()
#####
    print('Answer data file size: ', os.path.getsize('answer.data'))

    os.system('md5sum answer.data')
    
    # If only negativity and bitsize exists in answer.data
    if ((os.path.getsize('answer.data')) <= 162304):
        print('Computation failure: Answer Bit Size is too large')
    else:
        secret_key = 'secret.key'
        answer_data = 'answer.data'
        subprocess.call('./verif')
        #if(int(LASTOP) == 1):
            #print("multiverif32")
            #subprocess.call('./multi_verif32')
        #elif(int(LASTOP) == 2):
            #print("multiverif32")
            #subprocess.call('./multi_verif32')
        #elif(int(LASTOP) == 3):
            #print("multiverif32")
            #subprocess.call('./multi_verif32')
        #elif(int(LASTOP) == 4):
            #print("div_verif")
            #subprocess.call('./Div_verif')

    stop = time.perf_counter()
    time_elapsed1 = round((stop - dragonfly_time), 3)
    time_elapsed2 = round((stop - start), 3)
    print('Total time elapsed excluding Dragonfly Key Exchange:', time_elapsed1, 's')
    print('Total time elapsed including Dragonfly Key Exchange:', time_elapsed2, 's')
    os.system('python3 reset.py')




#############################################

# Create TCP/IP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_message = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#bind to own ip address for keygen message
own_ipaddr = '192.168.0.4'
own_address_kg = (own_ipaddr, 4380)

print("Hello!")
start = time.perf_counter()
x = 1
while (x != 0):
    expr = input("Enter an expression using letters (A, B, C) for clients and symbols ( +, -, *) for operators. [E.g. A + B * C]: ")

    usr_input_time = time.perf_counter()
    infix = InfixConverter()
    global postfix_expr
    postfix_expr = str(infix.toPostfix(expr))
    print('Postfix Expression: ',postfix_expr)
    
    # varList is a list of letters filtered from the postfix_expression
    varList = re.findall("[a-zA-Z]", postfix_expr)
    varNum = len(varList)


    # opList is a list of operators (-,+,*,/) filtered from the postfix_expression
    opList = re.findall("[-,+,*,/]", postfix_expr)
    print(opList)
    opNum = len(opList)
    
    global LASTOP


    # Check for number of letters (clients)
    if (varNum < 2):
        print("Please enter at least 2 letters (A-Z) that represent clients, and 1 operator")
        x = 1
    elif (varNum == 2) and (opNum == 1):
        while True:
            client1_ipaddr = input("Enter the IPv4 Address for "+varList[0]+": ")
            check = validateIP(client1_ipaddr)
            HOSTUP = True if os.system("ping -c 2 " + client1_ipaddr + " >/dev/null 2>&1") == 0 else False
            # HOSTUP = True if os.system("ping -c 2 " + client1_ipaddr.strip(";") + " | tee /proc/sys/vm/drop_caches >/dev/null 2>&1") == 0 else False
            if check == "IPv4" and HOSTUP:
            # if check == "IPv4":
                break
            else:
                print("\nPlease enter a valid and working IPv4 Address")
        while True:
            client2_ipaddr = input("Enter the IPv4 Address for "+varList[1]+": ")
            check = validateIP(client2_ipaddr)
            HOSTUP = True if os.system("ping -c 2 " + client2_ipaddr + " >/dev/null 2>&1") == 0 else False
            # HOSTUP = True if os.system("ping -c 2 " + client1_ipaddr.strip(";") + " | tee /proc/sys/vm/drop_caches >/dev/null 2>&1") == 0 else False
            if check == "IPv4" and HOSTUP:
                break
            else:
                print("Please enter a valid and working IPv4 Address")
        OPERATION1 = opList[0]    
        if (OPERATION1 == '+'):
            OPERATION1 = "1"    
        elif (OPERATION1 == '-'):
            OPERATION1 = "2"
        elif (OPERATION1 == '*'):
            OPERATION1 = "3"
        elif (OPERATION1 == '/'):
            OPERATION1 = "4"
        else:
            None
        LASTOP = OPERATION1
        x = 0

    elif (varNum == 3) and (opNum == 2):
        while True:
            client1_ipaddr = input("Enter the IPv4 Address for "+varList[0]+": ")
            check = validateIP(client1_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        while True:
            client2_ipaddr = input("Enter the IPv4 Address for "+varList[1]+": ")
            check = validateIP(client2_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        while True:
            client3_ipaddr = input("Enter the IPv4 Address for "+varList[2]+": ")
            check = validateIP(client3_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        OPERATION1 = opList[0]
        OPERATION2 = opList[1]
        if (OPERATION1 == '+'):
            OPERATION1 = "1"
        elif (OPERATION1 == '-'):
            OPERATION1 = "2"
        elif (OPERATION1 == '*'):
            OPERATION1 = "3"
        elif (OPERATION1 == '/'):
            OPERATION1 = "4"
        else:
            None
        if (OPERATION2 == '+'):
            OPERATION2 = "1"
        elif (OPERATION2 == '-'):
            OPERATION2 = "2"
        elif (OPERATION2 == '*'):
            OPERATION2 = "3"
        elif (OPERATION2 == '/'):
            OPERATION2 = "4"
        else:
            None
        
        LASTOP = OPERATION2
        x = 0
    elif (varNum == 4) and (opNum == 3):
        while True:
            client1_ipaddr = input("Enter the IPv4 Address for "+varList[0]+": ")
            check = validateIP(client1_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        while True:
            client2_ipaddr = input("Enter the IPv4 Address for "+varList[1]+": ")
            check = validateIP(client2_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        while True:
            client3_ipaddr = input("Enter the IPv4 Address for "+varList[2]+": ")
            check = validateIP(client3_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        while True:
            client4_ipaddr = input("Enter the IPv4 Address for "+varList[3]+": ")
            check = validateIP(client4_ipaddr)
            if check == "IPv4":
                break
            else:
                print("Please enter a valid IPv4 Address")
        OPERATION1 = opList[0]
        OPERATION2 = opList[1]
        OPERATION3 = opList[2]
        if (OPERATION1 == '+'):
            OPERATION1 = "1"
        elif (OPERATION1 == '-'):
            OPERATION1 = "2"
        elif (OPERATION1 == '*'):
            OPERATION1 = "3"
        elif (OPERATION1 == '/'):
            OPERATION1 = "4"
        else:
            None
        if (OPERATION2 == '+'):
            OPERATION2 = "1"
        elif (OPERATION2 == '-'):
            OPERATION2 = "2"
        elif (OPERATION2 == '*'):
            OPERATION2 = "3"
        elif (OPERATION2 == '/'):
            OPERATION2 = "4"
        else:
            None
        if (OPERATION3 == '+'):
            OPERATION3 = "1"
        elif (OPERATION3 == '-'):
            OPERATION3 = "2"
        elif (OPERATION3 == '*'):
            OPERATION3 = "3"
        elif (OPERATION3 == '/'):
            OPERATION3 = "4"
        else:
            None

        LASTOP = OPERATION3
        x = 0
    elif (varNum > 4) or (opNum > 3):
        print("Please do not enter more than 4 letters and 3 operators")
        x = 1
    else:
        print("Please enter a proper expression")
        x = 1

    usr_input_time_stop = time.perf_counter()
    global usr_input_time1
    usr_input_time1 = int(usr_input_time_stop - usr_input_time)


dragonfly()
