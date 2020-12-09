#!/usr/bin/python3
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
import logging

# THE PURPOSE OF THIS FILE IS TO INITATE DRAGONFLY KEY EXHANGE AND VERIFY ITS COMPLETION 

def dragonfly():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    output_address = ("192.168.0.4", 4380)
    

    print('Listening...')
    logging.info('STARTING dragonfly')

# else:
    #Execute dragonfly private for output machine
    print ('Executing dragonfly code for Output machine.')

    subprocess.run('./dragonfly_private_keygen.py')

    
    #Execute dragonfly public for cloud machine
    logging.info("dragonfly cloud")
    print ('executing dragonfly code for CLOUD machine')
    subprocess.run('./dragonfly_public_keygen.py')
    
    time.sleep(10)
    try:
        sock.connect(output_address)
        logging.info('Sending finished message')
        message = "finished"
        sock.sendall(message.encode())
        sock.close()
    except:
        pass


while True:
    dragonfly()
