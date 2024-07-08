# CS201-Project

## Execution instructions:
All 4 of the codes take user input, and return the corresponding outputs.<br />
The SHA-256, SHA-3 and BLAKE2b codes take the user input, store it as a string, calculate the hash of this string, and return the hash in hexadecimal format.<br />
The bc_vot_sys.cpp file, which is the code for the blockchain based voting system, needs to be compiled using OpenSSL. OpenSSL needs to be installed in the user's computer before execution, otherwise the code won't run. After installing OpenSSL, the user needs to update the includePath with the include folder path of the OpenSSL directory.<br />
Let's say that OpenSSL has been installed at the following address: "C:\Program Files\OpenSSL-Win64". Hence, for a Windows user, the file can be compiled like this, using Command Prompt:<br />
```
g++ -c bc_vot_sys.cpp -I"C:\Program Files\OpenSSL-Win64\include"
g++ bc_vot_sys.o -o bc_vot_sys.exe -L"C:\Program Files\OpenSSL-Win64\lib" -lssl -lcrypto
bc_vot_sys.exe
```

Upon execution, the user will get a menu interface, and needs to enter the appropriate options/commands to proceed and run the program. A test case has been given in bc_testcase.txt.<br />
A short ppt: [Blockchain-based voting system](https://docs.google.com/presentation/d/19OAUHt6ycafZmk4_ugiJ_ULXFlQXF3yK/edit?usp=sharing&ouid=115563981610636075357&rtpof=true&sd=true)
