import time
import hashlib
import random
import logging
import socket
import re, uuid
import base64
import os, random, struct
import subprocess
import asn1tools
from collections import namedtuple
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from optparse import *
import sys
import select

asn1_file = asn1tools.compile_files("asntest.asn")

#retrieve local hostname
local_hostname = socket.gethostname()

#get fully qualified hostname
local_fqdn = socket.getfqdn()

##########################################################
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


def decrypting(key, filename):
    chunksize = 64 * 1024
    outputFile = filename.split('.hacklab')[0]

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)

    return outputFile


def handshake():
    #Own MAC address
    own_mac = (':'.join(re.findall('..', '%012x' % uuid.getnode())))

    #Encode MAC address with BER
    own_mac_BER = asn1_file.encode('DataMac', {'data': own_mac})
    print ("my own MAC",own_mac)
    sta = Peer('abc1238', own_mac, 'STA')

    logger.info('Starting hunting and pecking to derive PE...\n')

    #Send own MAC address, BER encoded to peer
    sock_output.send(own_mac_BER)
    raw_other_mac = sock_output.recv(1024)

    #decode BER and get MAC address from peer
    other_decode_mac = asn1_file.decode('DataMac', raw_other_mac)
    other_mac = other_decode_mac.get('data')

    print ('MAC Received', other_mac)

    sta.initiate(other_mac)

    print()
    logger.info('Starting dragonfly commit exchange...\n')

    scalar_sta, element_sta = sta.commit_exchange()

    #Attempt to send BER encoded Scalar / Element AP to peer
    scalar_complete = ("\n".join([str(scalar_sta), str(element_sta)]))
    scalar_element_BER = asn1_file.encode('DataScalarElement', {'data':scalar_complete})
    sock_output.sendall(scalar_element_BER)
    print()
    print("Scalar element send", scalar_complete)
    logger.info('Computing shared secret...\n')

    #Received BER encoded Scalar / Element AP
    scalar_element_ap_encoded = sock_output.recv(1024)
    scalar_element_ap_decoded = asn1_file.decode('DataScalarElement', scalar_element_ap_encoded)
    scalar_element_ap = scalar_element_ap_decoded.get('data')

    print('Scalar element received', scalar_element_ap)
    data = scalar_element_ap.split('\n')
    # print (data[0])
    # print (data[1])
    scalar_ap = data[0]
    element_ap = data[1]
    print()
    print ('scalar_ap recv:',scalar_ap)
    print()
    print ('element_ap recv:',element_ap)
    print ()
    print ()
    namedtuple_element_ap = eval(element_ap)
    print (namedtuple_element_ap.y, namedtuple_element_ap.x)
    print ()
    print ()

    sta_token = sta.compute_shared_secret(namedtuple_element_ap, int(scalar_ap), other_mac)

    #Encode STA_Token to be BER encoded and send to peer
    staToken_BER = asn1_file.encode('DataStaAp', {'data':sta_token})
    sock_output.send(staToken_BER)
    print("sta_token ", sta_token)

    print()
    logger.info('Confirm Exchange...\n')

    #Received BER encoded AP Token and decode it
    apToken_encoded = sock_output.recv(1024)
    apToken_decoded = asn1_file.decode('DataStaAp', apToken_encoded)
    ap_token = apToken_decoded.get('data')

    print('received ap token', ap_token)
    
    PMK_Key = sta.confirm_exchange(ap_token)
    #print (PMK_Key)
    # time.sleep(1000)

    # Open the received cloud key from the key generator
    # open('OPERATION_AND_BER.hacklab', 'wb') as s:
    #       print ('File opened...\n')
    #       while True:

#####
    #Testing phase
    # buffer_size = 1

    buffer_size = 1024
    while True:
        try:
            #Listening and receive data
            OPERATION_AND_IP_BER = sock_output.recv(buffer_size)

            print("length of operation and ip", len(OPERATION_AND_IP_BER))
            print("Operation and IP BER", OPERATION_AND_IP_BER)

            #Decode BER
            OPERATION_AND_IP_decoded = asn1_file.decode('DataUserInput', OPERATION_AND_IP_BER)
        
            #Send success msg to output
            msg = "success"
            sock_output.send(msg.encode())

            #Break out of while loop if succeed
            break

        except:
            #Print error message
            print("An error occured", sys.exc_info()[0])

            #Empty out data from socket
            read_con = [sock_output]
            while True:
                r, w, e = select.select(read_con, [], [], 0.0)
                if len(r) == 0:
                    break
                else:
                    for data in r:
                        data.recv(1024)
            
            #Testing phase
            # buffer_size = int(input("Size of buffer?"))
            
            #Send fail message to output
            msg = "fail"
            sock_output.send(msg.encode())
            continue
#####

    #Print out operation and IP
    print("Operation and IP data", OPERATION_AND_IP_decoded)

    # Define global lists for ipaddresses and operation codes
    global ipList
    ipList = []

    global opList
    opList = []

    global numClList
    numClList = []

    # Create variables for each ipaddress and operation
    for k1, v1 in OPERATION_AND_IP_decoded.items():
        for k2,v2 in v1.items():
            locals()[k2] = k2
            print('key',k2)
    
    postfix_expr = OPERATION_AND_IP_decoded['postfix']['postfix']
    print('Postfix: ',postfix_expr)
    p = open('postfix.hacklab', 'wb')
    p.write(postfix_expr)
    p.close()
    decrypting(PMK_Key, 'postfix.hacklab')
    p = open('postfix', 'r')
    postfix = str(p.read())
    p.close()
    print("The postfix expression is: ",postfix)
    global postfixList
    postfixList = " ".join(postfix)
    postfixList = postfixList.split()
    print("POSTFIX LIST", postfixList)
    
    numClList = re.findall("[a-zA-Z]", postfix)
    sock_output.close()

    # iterate through postfixList to sort alpha char and operators
    x = 0
    y = 0
    for i in postfixList:
        if (i.isalpha()):
            CLI = OPERATION_AND_IP_decoded['ipaddress']['ipaddress{0}'.format(x+1)]
            print("Client :", CLI)
            c = open("client.hacklab", "wb")
            c.write(CLI)
            c.close()
            decrypting(PMK_Key, 'client.hacklab')
            c = open("client", "r")
            CLIENT = c.read()
            c.close()
            ipList.append(CLIENT)
            print(ipList)
            os.remove('client')
            os.remove('client.hacklab')
            x = x + 1
        else:
            OPCODE = OPERATION_AND_IP_decoded['operation']['operation{0}'.format(y+1)]
            print("Opcode:", OPCODE)
            o = open("opcode.hacklab","wb")
            o.write(OPCODE)
            o.close()
            decrypting(PMK_Key, 'opcode.hacklab')
            o = open("opcode", "r")
            OPCODE = o.read()
            o.close()
            opList.append(OPCODE)
            print(opList)
            os.remove('opcode')
            os.remove('opcode.hacklab')
            y = y + 1

            print(len(ipList))
            if (len(ipList) == 1) or (len(numClList) ==1):
                print(ipList)
                compute_final()
            elif (len(ipList) > 1) and (len(numClList) >1):
                print(ipList)
                computation()
            else:
                None
    answer()
    sys.exit()

##########################################################

def computation():
    print("ip list",ipList)
    print("op list",opList)
    time.sleep(5)
    
    # pop the last element of ipList
    CL_A = ipList.pop()
    numClList.pop(0)
    cipher((CL_A, 4381))

    time.sleep(5)

    # pop the next last element of ipList
    CL_B = ipList.pop()
    numClList.pop(0)
    cipher_ab((CL_B, 4381))

    # At this stage cloud.data should contain the ciphertexts from 2 CL
    compute()
    
def cipher(client_address):

    data_request_time_start = time.perf_counter()

    while True:
        try:
            sockA.connect(client_address)
            break
        except ConnectionRefusedError as conn_error:
            print('A connection error has occured')
            print(conn_error)
            print('Attempting to connect to client again')
            time.sleep(5)
        except KeyboardInterrupt:
            print('Crtl-C pressed to terminate program')
            pass
        except:
            print('Unexpected error: ',sys.exc_info()[0])

    # Open the cloud data received from client and write to cloud.data

#####
    BUFFER_SIZE = 1032
    with open('cloud.data', 'wb') as f:
        print ('Cloud data file opened...\n')
    
        #Size of cloud data
        while True:
            try:
                msg = sockA.recv(BUFFER_SIZE)
                fsize_decoded = asn1_file.decode("DataFsize", msg)
                fsize = int(fsize_decoded.get("data"))

                #Send success msg to output
                msg = "success"
                sockA.send(msg.encode())

                #Break out of while loop if succeed
                break

            except:
                #Print error message
                print("An error occured", sys.exc_info()[0])

                #Empty out data from socket
                read_con = [sockA]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)
                    
                #Testing phase
                # buffer_size = int(input("Size of buffer?"))
                
                #Send fail message to output
                msg = "fail"
                sockA.send(msg.encode())
                continue

        #Received size
        rsize = 0

        # Decode received cloud data from BER
        while True:
            try:
                while True:
                    print ('Receiving cloud data...\n')
        
                    #BER receive data and decode
                    cloud_data = sockA.recv(BUFFER_SIZE)

                    #Testing phase
                    # BUFFER_SIZE -=10

                    print("Length of cloud data",len(cloud_data))
                    print(cloud_data)
                    cloud_data_decoded_dict = asn1_file.decode("DataContent", cloud_data)
                    cloud_data_decoded_raw = cloud_data_decoded_dict.get("data")

                    #Writing data
                    f.write(cloud_data_decoded_raw)

                    #Send success message to client
                    msg = "success"
                    sockA.sendall(msg.encode())

                    #Break occur if all data is received
                    rsize = rsize + len(cloud_data_decoded_raw)
                    if rsize >= fsize:
                        print ('Breaking from file write')
                        break
            except:
                #Print error message
                print("An error occured:", sys.exc_info()[0])

                #Empty out data from socket
                read_con = [sockA]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)

                #Testing phase
                # BUFFER_SIZE = int(input("sock a, Size of buffer size?\n"))

                #Send fail message to client
                msg = "fail"
                sockA.send(msg.encode())
                continue
            
            else:
                #Break out of while loop
                if rsize >= fsize:
                    print ('Received everything.. Breaking out')
                    break
#####
        f.close()
        print ('Successfully got the file\n')

    # Send notice to the client;
    indicator = asn1_file.encode('DataIndicator', {'data':"Hello! cloud.data received"})
######
    while True:
        sockA.send(indicator)

        #Receive msg
        encode_msg = sockA.recv(1024)
        msg = encode_msg.decode()

        print(msg)

        #if success break
        if (msg == "success"):
            break
        else:
            continue
######
    print("Sending an indicator...\n")
    print('Cloud data file size: ', os.path.getsize('cloud.data'))
    sockA.close()

    data_request_time_stop = time.perf_counter()
    global data_request_time1
    data_request_time1 = round((data_request_time_stop - data_request_time_start), 3)
    f = open('timings.txt', 'a')
    f.write('\nThe total time elapsed for data request for client 1 is: ')
    f.write(str(data_request_time1))
    f.close

def cipher_ab(client_address):
    # This function appends to cloud.data instead of overwriting it.

    data_request_time_start2 = time.perf_counter()

    while True:
        try:
            sockB.connect(client_address)
            break
        except ConnectionRefusedError as conn_error:
            print('A connection error has occured')
            print(conn_error)
            print('Attempting to connect to client again')
            time.sleep(5)
        except KeyboardInterrupt:
            print('Crtl-C pressed to terminate program')
            pass
        except:
            print('Unexpected error: ',sys.exc_info()[0])
    # Open the cloud data received from client and write to cloud.data

#####
    BUFFER_SIZE = 1032
    with open('cloud.data', 'ab') as f:
        print ('Cloud data file opened...\n')
       
        while True:
            try:
                msg = sockB.recv(BUFFER_SIZE)
                fsize_decoded = asn1_file.decode("DataFsize", msg)
                fsize = int(fsize_decoded.get("data"))

                #Send success
                msg = "success"
                sockB.send(msg.encode())

                #Break out of while loop if succeed
                break
            
            except:
                #Print error message
                print("An error occured", sys.exc_info()[0])

                #Empty out data from socket
                read_con = [sockB]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)
                    
                #Testing phase
                # BUFFER_SIZE = int(input("fSize of buffer?"))
                
                #Send fail message to output
                msg = "fail"
                sockB.send(msg.encode())
                continue

        #Received size
        rsize = 0
        
        while True:
            try:
                while True:
                    print ('Receiving cloud data...\n')
  
                    #Received BER data and decode
                    cloud_data = sockB.recv(BUFFER_SIZE)

                    #Testing phase
                    # BUFFER_SIZE -=10

                    cloud_data_decoded_dict = asn1_file.decode("DataContent", cloud_data)
                    cloud_data_decoded_raw = cloud_data_decoded_dict.get("data")
                    print ('Cloud Data: ', cloud_data_decoded_raw)

                    #Writing data
                    f.write(cloud_data_decoded_raw)

                    #Send success message to client
                    msg = "success"
                    sockB.sendall(msg.encode())

                    #Break occur if all data is received
                    rsize = rsize + len(cloud_data_decoded_raw)
                    if rsize >= fsize:
                        print ('Breaking from file write')
                        break

            except:
                #Print error message
                print("An error has occured:", sys.exc_info()[0])

                #Empty out data from socket
                read_con = [sockB]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)

                #Testing phase
                # BUFFER_SIZE = int(input("sock a, Size of buffer size?\n"))

                #Send fail message to client
                msg = "fail"
                sockB.send(msg.encode())
                continue

            else:
                #Break out of while loop
                if rsize >= fsize:
                    print ('Received everything.. Breaking out')
                    break

#####
        f.close()
        print ('Successfully got the file\n')

    # Send notice to the client;
    indicator = asn1_file.encode('DataIndicator', {'data':"Hello! cloud.data received"})
######
    while True:
        sockB.send(indicator)

        #Receive msg
        encode_msg = sockB.recv(1024)
        msg = encode_msg.decode()

        print(msg)

        #if success break
        if (msg == "success"):
            break
        else:
            continue
######
    print("Sending an indicator...\n")
    print('Cloud data file size: ', os.path.getsize('cloud.data'))
    sockB.close()
    data_request_time_stop2 = time.perf_counter()
    data_request_time2 = round((data_request_time_stop2 - data_request_time_start2), 3)
    f = open('timings.txt', 'a')
    f.write('\nThe total time elapsed for data request for client2 is: ')
    f.write(str(data_request_time2))
    f.close


def cipher2(client_address):
    data_request_time_start = time.perf_counter()
    while True:
        try:
            sock.connect(client_address)
            break
        except ConnectionRefusedError as conn_error:
            print('A connection error has occured')
            print(conn_error)
            print('Attempting to connect to client again')
            time.sleep(5)
        except KeyboardInterrupt:
            print('Crtl-C pressed to terminate program')
            pass
        except:
            print('Unexpected error: ',sys.exc_info()[0])

#####
    BUFFER_SIZE = 1032

    #Testing phase
    # BUFFER_SIZE = 3

    with open('cloud.data', 'wb') as f:
        print ('Cloud data file opened...\n')
        
        #Size of cloud data
        while True:
            try:
                msg = sock.recv(BUFFER_SIZE)
                fsize_decoded = asn1_file.decode("DataFsize", msg)
                fsize = int(fsize_decoded.get("data"))

                #Send success msg to output
                msg = "success"
                sock.send(msg.encode())

                #Break out of while loop if succeed
                break
            
            except:
                #Print error message
                print("An error occured", sys.exc_info()[0])

                #Empty out data from socket
                read_con = [sock]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)
                
                #Testing phase
                # BUFFER_SIZE = int(input("Size of buffer?"))
                
                #Send fail message to output
                msg = "fail"
                sock.send(msg.encode())
                continue

        #Received size
        rsize = 0
        
        # Decode received cloud data from BER
        while True:
            try:
                while True:
                    print ('Receiving cloud data...\n')
                    
                    #BER received and decode
                    cloud_data = sock.recv(BUFFER_SIZE)

                    #Testing phase
                    # BUFFER_SIZE -=10

                    cloud_data_decoded_dict = asn1_file.decode("DataContent", cloud_data)
                    cloud_data_decoded_raw = cloud_data_decoded_dict.get("data")
                    print(cloud_data)

                    #Writing to file
                    f.write(cloud_data_decoded_raw)

                    #sending success message to client
                    msg = "success"
                    sock.sendall(msg.encode())

                    #Break occur if all data is received
                    rsize = rsize + len(cloud_data_decoded_raw)
                    if rsize >= fsize:
                        print ('Breaking from file write')
                        break
            except:
                #Print error message
                print("An error occured:", sys.exc_info()[0])

                #Empty out data from socket
                read_con = [sock]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)

                #Testing phase
                # BUFFER_SIZE = int(input("sock a, Size of buffer size?\n"))

                #Send fail message to client
                msg = "fail"
                sock.send(msg.encode())
                continue

            else:
                #Break out of while loop
                if rsize >= fsize:
                    print ('Received everything.. Breaking out')
                    break

#####
    f.close()
    print ('Successfully got the file\n')

    # Send notice to the client;
    indicator = asn1_file.encode('DataIndicator', {'data':"Hello! cloud.data received"})

######
    while True:
        sock.send(indicator)
        #Receive msg
        encode_msg = sock.recv(1024)
        msg = encode_msg.decode()

        print(msg)

        #if success break
        if (msg == "success"):
            break
        else:
            continue
######
    print("Sending an indicator...\n")
    print('Cloud data file size: ', os.path.getsize('cloud.data'))
    sock.close()

    data_request_time_stop = time.perf_counter()
    data_request_time3 = round((data_request_time_stop - data_request_time_start), 3)
    f = open('timings.txt', 'a')
    f.write('\nThe total time elapsed for data request for client 3 is: ')
    f.write(str(data_request_time3))
    f.close



def compute():
    
    operator = int(opList.pop(0))


    # NOTE: change the subprocess file as required, when available
    if operator == 1:
        compute_time_start = time.perf_counter()
        # The user has chosen the Addition function
        # Run C++ Adder_cloud to compute answer
        subprocess.call("./add")
        print("Printing addition answer data...\n")
        compute_time_stop = time.perf_counter()
        compute_time_final = round((compute_time_stop - compute_time_start), 3)
        f = open('timings.txt','a')
        f.write('\nComputation time: ')
        f.write(str(compute_time_final))
        f.close()
    elif operator == 2:
        compute_time_start = time.perf_counter()
        # The user has chosen the Subtraction function
        # Run C++ subtract_cloud to compute answer
        subprocess.call("./sub")
        print("Printing subtraction answer data...\n")
        compute_time_stop = time.perf_counter()
        compute_time_final = round((compute_time_stop - compute_time_start), 3)
        f = open('timings.txt','a')
        f.write('\nComputation time: ')
        f.write(str(compute_time_final))
        f.close()
    elif operator == 3:
        compute_time_start = time.perf_counter()
        # The user has chosen the Multiplication function
        # Run C++ Multiply_cloud to compute answer
        subprocess.call("./multi32")
        print("Printing multiplication answer data...\n")
        compute_time_stop = time.perf_counter()
        compute_time_final = round((compute_time_stop - compute_time_start), 3)
        f = open('timings.txt','a')
        f.write('\nComputation time: ')
        f.write(str(compute_time_final))
        f.close()
    elif operator == 4:
        compute_time_start = time.perf_counter()
        # The user has chosen the Division function
        # Run C++ Divide_cloud to compute answer
        subprocess.call("./div")
        print("Printing division answer data...\n")
        compute_time_stop = time.perf_counter()
        compute_time_final = round((compute_time_stop - compute_time_start), 3)
        f = open('timings.txt','a')
        f.write('\nComputation time: ')
        f.write(str(compute_time_final))
        f.close()
    else:
        None

    # Print size of answer.data
    answer_data = 'answer.data'
    print("File size of computed answer file: ", os.path.getsize(answer_data))


def compute_final():

    CL_C = ipList.pop()
    numClList.pop(0)
    cipher2((CL_C, 4381))


    # copy binary contents of answer.data to append to cloud.data
    with open('answer.data', 'rb') as a:
        answer = a.read(8192)
        with open('cloud.data', 'ab') as c:
            while answer:
                c.write(answer)
                answer = a.read(8192)
    os.remove('answer.data')
    compute()
    
def answer():

    answer_data = "answer.data"
    print("This file ", answer_data, "is our computed answer\n")

    # Open the file and read its content
    # f = open('answer.data', 'rb')
    # answer = f.read(8192)

    # Open socket connection to OUTPUT to send Answer
    output_ipaddr = "192.168.0.4"
    output_address =(output_ipaddr, 4381)

    sock_output2.connect(output_address)
    print ("connecting to", output_ipaddr)

    # Encode ans_size in BER
    # Send size of answer file to the client
    # Send answer file to output
    ans_size = os.path.getsize(answer_data)
    ans_size_encoded = asn1_file.encode('DataAnsSize', {'data':ans_size})

    while True:
        sock_output2.send(ans_size_encoded)

        #receive msg
        encode_msg = sock_output2.recv(1024)
        msg = encode_msg.decode()

        print(ans_size_encoded)

        #if success, break
        if (msg == "success"):
            break
        else:
            continue
  
    print("Sending answer...\n")

    # Read the final answer file and send it to the OUTPUT
    # with open('answer.data', 'rb') as f:
    # answer = f.read(1032)

#####
    #Get size of answer.data
    answ_data_size = os.path.getsize("answer.data")
    print("Size of answer.data is", answ_data_size)

    #set offset value
    offset_value = 0

    #Testing x value
    with open('answer.data', 'rb') as f:
        while True:
            print("offset",f.tell())
            #Before offset
            before_offset = f.tell()
            answer = f.read(1032)

            #BER encode answer & send
            answer_encoded = asn1_file.encode('DataAnswer', {'data':answer})
            sock_output2.sendall(answer_encoded)
            
            #after offset
            after_offset = f.tell()

            #receving msg
            encode_msg = sock_output2.recv(1024)
            msg = encode_msg.decode()
            
            #success message
            if (msg == "success"):
                #close socket if all data send
                print(answ_data_size)
                print(after_offset)
                if (int(after_offset == answ_data_size)):
                    sock_output2.shutdown(socket.SHUT_RDWR)
                    sock_output2.close()
                    break
                #fail message
                else:
                    continue
            else:
                #offset differences
                offset_differences = int(after_offset) - int(before_offset)
                
                #offset value
                offset_value = int(after_offset) - int(offset_differences)
                f.seek(offset_value)

#####
    f.close()
    print("File size of computed answer file: ", os.path.getsize(answer_data))
    os.system("md5sum answer.data")
    os.remove('answer.data')
    sock_output2.close()

if __name__ == '__main__':

    sockA = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockB = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_output = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_output2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    output_ipaddr = "192.168.0.4"
    output_address =(output_ipaddr, 4381)
    while True:
        try:
            sock_output.connect(output_address)
            break
        except ConnectionRefusedError as conn_error:
            print('A connection error has occured')
            print(conn_error)
            print('Attempting to connect to OUTPUT again')
            time.sleep(5)
        except KeyboardInterrupt:
            print('Crtl-C pressed to terminate program')
            pass
        except:
            print ("connecting to", output_ipaddr)

    handshake()
