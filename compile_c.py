#!/usr/bin/python3
import os
import glob

qn = str(input("Is BOOST Library installed? (yes/no) ")).lower()
if qn == "no":
	os.system("apt-get install libboost-all-dev -y")

files = glob.glob("*/*.c")

if len(files) <= 0:
        print("No c files found!")
        sys.exit()

for filename in files:
	filestriped = filename[:-2]
	os.system(f"g++ {filename} -o {filestriped} -ltfhe-spqlios-fma")

	print(f"\nCompiling {filename}")

print(f"\n{len(files)} files compiled")
	
