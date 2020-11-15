# Integer Expressions using Arithmetic Circuit Homomorphic Encryption
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![GitHub repo size](https://img.shields.io/github/repo-size/kennethsoh/IE-ACHE)
![GitHub issues](https://img.shields.io/github/issues/kennethsoh/IE-ACHE)

This is an extension of an ongoing research project on Arithmetic Circuit Homomorphic encryption (ACHE) which was implemented based on Fast Fully Homomorphic Encryption over the Torus (TFHE). This iteration focuses on integrating ASN.1 Basic Encoding Rule for the purpose of computing results of integer expressions up to 3 operands. The previous version of the project can be found <a href="https://github.com/powderfool000/ambitioushomo" target="_blank">here</a>.

This system is configured and tested for Ubuntu 20.04 LTS



#### Dependencies
* Python3 and Pip3
``` bash
$ sudo apt-get install python3 python3-pip

# Check python3 installation
$ which python3
> /usr/bin/python3
```

* ASN.1 Tools (https://pypi.org/project/asn1tools/)
* PyCryptodome (https://pypi.org/project/pycryptodomex/)
```bash
$ pip3 install asn1tools pycryptodomex
```

* Fast Fully Homomorphic Encryption over the Torus (https://github.com/tfhe/tfhe)
```bash
$ cd /
$ git clone --recurse-submodules --branch=master https://github.com/tfhe/tfhe.git
$ cd tfhe
$ mkdir build; cd build
$ ccmake ../src

# Press 'c' to configure, then 'g' to generate

$ make
$ make install
```

#### Installation Guide
1. Clone this repository
```bash
$ cd /
$ git clone https://github.com/kennethsoh/IE-ACHE.git
$ cd IE-ACHE

# Provide executable permissions if needed
$ chmod u+x */*
```

2. Repeat dependency installation and Step 1 minimally 4 times for 4 different machines: Client(1/2/3), Cloud, Keygen and Output.

3. Assign IP Addresses for machines as follows:<br>
```
Cloud:    192.168.0.1
Client1:  192.168.0.21
Client2:  192.168.0.22
Client3:  192.168.0.23
Keygen:   192.168.0.3
Output:   192.168.0.4
```

4. Add the service files in 'Services' folder to ```/etc/systemd/system/```. Edit the <u>Users</u>, <u>WorkingDirectory</u> and <u>ExecStart</u> values if necessary. Default values assume that this repository is installed at root (/) directory and root user is used. 

5. Start the services on each machine
```
$ systemctl daemon-reload
$ systemctl enable MP MP2
$ systemctl start MP MP2
```

6. Run output_dynamic.py on Output machine
```
Output$ cd /IE-ACHE/Output
Output$ python3 output_dynamic.py
```
