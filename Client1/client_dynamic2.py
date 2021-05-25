#!/usr/bin/python3
import subprocess
import time
import os

print("Running SIDH cipher")
while True:
    os.system('python3 sidh_cipher_client.py')
    # time.sleep(5)
    # os.remove('secret.key.hacklab')