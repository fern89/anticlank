# Solution
Players are expected to realize that due to the timing of the printout, the code printing `incorrect flag` should be within proximity to the flagchecker code. This observation is **not mandatory**, though it will greatly simplify the solution. Players may still use hardware watchpoints if they are unable to make this observation.

Players are also required to observe that the process creates many forks and adjust their solutions accordingly.

After making the observations, players may use eBPF to hook any syscall write to stdout. They may run the following command:
```
$ sudo bpftrace --unsafe -e '
tracepoint:raw_syscalls:sys_enter 
/comm=="chal" && args->id==1 && args->args[0]==1/ 
{ 
    if (!@seen[pid]) { 
        @seen[pid] = 1; 
        @count++; 
        if (@count == 2) { 
            printf("%d", pid); 
            signal("SIGSTOP"); 
            exit(); 
        } 
    } 
}'
```

This hooks the `write` syscall, and only triggers on the second `chal` process that calls it. This prevents the filter from prematurely firing on the `enter your flag` prompt.

Players can then run `./chal`, and enter an arbitrary flag. In a few seconds, the eBPF filter will trigger, printing out a PID of a suspended process. This process should contain the decrypted flagchecker.

Attaching `gdb` to the suspended process with `gdb attach [pid]`, players can then run the `search-pattern` command (or equivalent, depending on their installed gdb extension) to look for the flag format. In this case, the flag format is `CTF{`.

```
gef> search-pattern "CTF{"
[+] Searching for 'CTF{' in whole memory
[+] In '/tmp/chal (deleted)' 0x4b5000-0x692000 [rwx] (0x1dd000 bytes)
  0x0000005bf43d:    43 54 46 7b 69 5f 61 6d  48 ba 5f 68 61 78 78 6f    |  CTF{i_amH._haxxo  |
[+] In '[stack]' 0x7fff58da5000-0x7fff58e49000 [rw-] (0xa4000 bytes)
  0x7fff58da5a40:    43 54 46 7b 69 5f 61 6d  5f 68 61 78 78 6f 72 7d    |  CTF{i_am_haxxor}  |
[+] Searching for 'C\x00T\x00F\x00{\x00' in whole memory
gef> 
```

The flag is very clearly shown in the printed output, thus solving the challenge.

Flag: `CTF{i_am_haxxor}`
