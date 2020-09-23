# Applying Basic Encoding Rule (ITU-T X.690) on Integer Expressions using Arithmetic Circuit Homomorphic Encryption

This is an extension of an ongoing research project on Arithmetic Circuit Homomorphic encryption (ACHE) which was implemented based on Fast Fully Homomorphic Encryption over the Torus (TFHE). This iteration focuses on integrating ASN.1 Basic Encoding Rule for the purpose of computing results of integer expressions up to 3 operands.

This system is configured and tested for Ubuntu 20.04 LTS

#### Dependencies

* ASN.1 Tools (https://pypi.org/project/asn1tools/)
* Fast Fully Homomorphic Encryption over the Torus (https://github.com/tfhe/tfhe)
* Homomorphic encryption and Dragonfly SAE (https://github.com/powderfool000/ambitioushomo)

#### Installation Guide
1. Download or clone this repository
```bash
git clone https://github.com/kennethsoh/Integer-Expression-Homomorphic-Encryption.git
cd Integer-Expression-Homomorphic-Encryption
```

2. Copy each sub folder (Client1, Client2, Client3, Cloud, Keygen & Output) into its own virtual machine or hardware machine. <br>
You will need minimally 4 machines for 1 Client, Cloud, Keygen and Output.

3. Assign IP Addresses for machines as follows:<br>
```
Cloud:    192.168.0.1
Client1:  192.168.0.21
Client2:  192.168.0.22
Client3:  192.168.0.23
Keygen:   192.168.0.3
Output:   192.168.0.4
```

4. Add the service files in 'Services' folder to ```/etc/systemd/system/```. Edit the Users, WorkingDirectory and ExecStart values if necessary.

5. Start the services on each machine
```
systemctl daemon-reload
systemctl enable MP MP2
systemctl start MP MP2
```

6. Run output_dynamic.py on Output machine


