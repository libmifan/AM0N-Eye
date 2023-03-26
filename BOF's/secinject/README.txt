## Section Mapping Process Injection (secinject): AM0N-Eye BOF

Beacon Object File (BOF) that leverages Native APIs to achieve process injection through memory section mapping.
one to inject beacon shellcode for a selected listener into the desired process, and one to inject the user's desired shellcode - loaded from a bin file - into the desired process.  These are *sec-inject* and *sec-shinject* respectively.

- Currently, this is only implemented for x64 processes.

### How to Make
```
cd secinject/src
make
```

### How to Use
#### Injecting Beacon
```
sec-inject PID LISTENER-NAME
```

#### Injecting Other Shellcode
```
sec-shinject PID /path/to/bin
```
