#!/usr/bin/python3
# This file compiles all c files in the repository
import os
import sys
import glob

qn = str(input("Is BOOST Library installed? (yes/no) ")).lower()
if qn == "no":
    opsystem  = str(input("Are you on Linux or macOS? (linux/macos) ")).lower()
    if opsystem == "linux":
        os.system("apt-get install libboost-all-dev -y")

        files = glob.glob("*/*.c")
        if len(files) <= 0:
            print("No c files found!")
            sys.exit()

            for filename in files:
                filestriped = filename[:-2]
                os.system(f"g++ {filename} -o {filestriped} -ltfhe-spqlios-fma")

                print(f"\nCompiling {filename}")

        os.system("chmod u+x */*")
        print(f"\n{len(files)} files compiled. Please check for errors in compliation.")

    elif opsystem == "macos":
        os.system("brew install boost")

        files = glob.glob("*/*.c")
        if len(files) <= 0:
            print("No c files found!")
            sys.exit()

        for filename in files:
            filestriped = filename[:-2]
            os.system(f"g++ {filename} -o {filestriped} -ltfhe-spqlios-fma")

            print(f"\nCompiling {filename}")

        os.system("chmod u+x */*")
        print(f"\n{len(files)} files compiled. Please check for errors in compliation.")
    else:
        print("You did not specify an operating system (linux/macos). BOOST will not be installed.")
        print("No action taken. Have a nice day :)")

elif qn == "yes":
    files = glob.glob("*/*.c")

    if len(files) <= 0:
        print("No c files found!")
        sys.exit()

    for filename in files:
        filestriped = filename[:-2]
        os.system(f"g++ {filename} -o {filestriped} -ltfhe-spqlios-fma")

        print(f"\nCompiling {filename}")


    os.system("chmod u+x */*")
    print(f"\n{len(files)} files compiled. Please check for errors in compliation.")

else:
    print("No action taken. Have a nice day :)")
