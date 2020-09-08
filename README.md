# Integer-Expression-Homomorphic-Encryption

This is an extension of an ongoing research project on Arithmetic Circuit Homomorphic encryption (ACHE) which was implemented based on Fast Fully Homomorphic Encryption over the Torus (TFHE). This iteration focuses on integrating ASN.1 Basic Encoding Rule for the purpose of calculating results of integer expressions up to 3 operands.

#### Dependencies

* Fast Fully Homomorphic Encryption over the Torus (https://github.com/tfhe/tfhe)
* Homomorphic encryption and Dragonfly SAE (https://github.com/powderfool000/ambitioushomo)

#### Installation Guide
1. Download or clone this repository
```bash
git clone https://github.com/kennethsoh/Integer-Expression-Homomorphic-Encryption.git
cd Integer-Expression-Homomorphic-Encryption
```

2. Copy each sub folder (Client1, Client2, Client3, Cloud, Keygen & Output) into its own virtual machine or hardware machine. You will need minimally 4 machines for 1 Client, Cloud, Keygen and Output.

3. Assign IP Addresses for machines as follows:
Cloud:    192.168.0.1
Client1:  192.168.0.21
Client2:  192.168.0.22
Client3:  192.168.0.23
Keygen:   192.168.0.3
Output:   192.168.0.4

