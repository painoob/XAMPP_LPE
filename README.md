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

Description:
In XAMPP for Windows version 7.2.9-0, the xampp_start.exe file located at C:\xampp\xampp_start.exe is installed with insecure permissions. Specifically, the Authenticated Users group has (M) (Modify) permission on the file, which allows any standard local user to overwrite the executable.

Since xampp_start.exe is executed with SYSTEM privileges (e.g., via Windows service, scheduled task, or autorun configuration), an attacker can replace the binary with a malicious executable such as a reverse shell. Upon system reboot, the attacker gains arbitrary code execution as NT AUTHORITY\SYSTEM.

Permissions Output (icacls) fo C:\xampp\xampp_start.exe :

`
BUILTIN\Administrators:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Users:(I)(RX)
NT AUTHORITY\Authenticated Users:(I)(M)
`



Proof of Concept (PoC):

1 - Log in as a standard user.

2 - Replace C:\xampp\xampp_start.exe with a reverse shell or other SYSTEM payload.

3 - Reboot the machine.

4 - Observe the payload executing as SYSTEM (whoami → NT AUTHORITY\SYSTEM).

