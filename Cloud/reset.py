import os

try:
    os.remove("answer.data")
    os.remove("client.hacklab")
    os.remove("opcode.hacklab")
    os.remove("cloud.data")
    os.remove("cloud.key")
    os.remove("cloud.key.hacklab")
    os.remove("postfix")
    os.remove("postfix.hacklab")
    os.remove("dragonfly.log")
    os.remove("averagestandard.txt")
except:
    pass
