# Simonware Network Audit

Run it from your own PC or laptop. It finds the Windows devices on a network and shows:
- **Windows version and build**, and whether Microsoft still supports it
- **Chrome, Edge, Firefox, Brave and Opera** versions, and whether Chrome, Edge and Firefox are **up to date** (checked live against Google, Microsoft and Mozilla)

```powershell
irm https://raw.githubusercontent.com/Simonsk19-maker/network-audit/main/Simonware-NetworkAudit.ps1 | iex
```

You get a table on screen, plus a **spreadsheet (CSV)** and a **web-page report** in `Desktop\Simonware Reports`.

For each PC it collects:
- **Windows:** version, build, and whether Microsoft still supports it
- **Browsers:** Chrome, Edge, Firefox, Brave, Opera, with up-to-date checks on the first three
- **Hardware:** make, model, serial number, CPU, RAM, disk size and free space
- **Security:** antivirus (on/off/out of date), firewall, BitLocker encryption, TPM, Secure Boot, local admin accounts
- **Windows Update:** date of the last update, and whether a restart is pending
- **Network:** IP and MAC address, wired or Wi-Fi, and whether Remote Desktop is on

The report flags anything that needs attention: out-of-support Windows, browsers due an update, antivirus off or missing, drives not encrypted, and PCs waiting for a restart.

## Choosing devices
1. **Scan this network automatically**
2. **Scan a range** you type, e.g. `192.168.1.0/24` (up to /22)
3. **Active Directory**: every enabled computer in the domain
4. **Names or IPs** you type, or a `.txt` file with one per line

## Domain networks
- Sign in to your laptop with a **domain admin** account, or enter one when asked.
- Devices are checked with **PowerShell Remoting** if it's on, otherwise **WMI**. On most domains one of these is already allowed. If not, turn on WinRM with Group Policy, or run option 5 on the PC.

## Networks without a domain (workgroups)
Windows blocks remote checks by default, so set up each PC **once**:
1. On each PC, open **PowerShell as Administrator** and run the command above.
2. Choose **5. Prepare THIS PC**. It turns on PowerShell Remoting and allows WMI through the firewall.
3. Give every PC an admin account with the **same username and password** (or use the built-in `Administrator` account).

When you run the audit, enter that account with **just the username**, e.g. `Administrator`.

> Option 5 can also allow other local admin accounts to connect remotely (`LocalAccountTokenFilterPolicy`). That makes remote admin logins more powerful, so only turn it on for networks you manage, with strong passwords.

## Notes
- Windows support dates are kept in a table at the top of the script (`$SwWindowsLifecycle`). Add new Windows versions there as Microsoft releases them.
- Browsers installed **per user** (in AppData) are found too, for every user who has signed in to the PC.
- Devices that couldn't be checked are listed with the reason, e.g. "Access denied" or "No answer".
- Most PCs are checked over **PowerShell Remoting**, which gets everything. If a PC falls back to **WMI**, a few security items (Secure Boot, local admins, reboot-pending) can't be read and are left blank. Running option 5 on the PC avoids this.
