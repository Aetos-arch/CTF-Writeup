# Instructions

You've discovered that your computer has been infected by a ransomware group that has encrypted a photo that's very important to you. This photo, which was stored on your desktop, is now inaccessible. You decide to conduct a digital investigation to recover the file and identify those responsible for the infection.

Your objective is to recover the following information:

- The name of the malicious process responsible for encrypting the file, and its process identifier (PID).
- The name and process ID of the infection vector(s) responsible for spreading the ransomware.
- The decrypted file and the flag it contains.
- The original URL from which the photo was downloaded.

Implement the necessary steps to recover this crucial information as part of your digital investigation.

# Identify which profile you're investigating

Using the command `volatility3 -f <path_to_dump_file> windows.info`, I extracted Windows operating system profile information from the memory dump file. Here's some key information provided in the result:
```c 
python3 vol.py -f fcsc.dmp windows.info > investigation/windows.info.txt

Volatility 3 Framework 2.4.2
Variable              Value
Kernel Base           0xf8054b615000
DTB                   0x1aa000
Symbols               file:///home/aetos/Documents/Forensics/Logiciels/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/3789767E34B7A48A3FC80CE12DE18E65-1.json.xz
Is64Bit               True
IsPAE                 False
layer_name            0 WindowsIntel32e
memory_layer          1 Elf64Layer
base_layer            2 FileLayer
KdVersionBlock        0xf8054c224398
Major/Minor           15.19041
MachineType           34404
KeNumberProcessors    4
SystemTime            2023-04-17 17:24:50
NtSystemRoot          C:\Windows
NtProductType         NtProductWinNt
NtMajorVersion        10
NtMinorVersion        0
PE MajorOperatingSystemVersion   10
PE MinorOperatingSystemVersion   0
PE Machine            34404
PE TimeDateStamp      Mon Nov 24 23:45:00 2070
```
The result of the `volatility3 -f <path_to_dump_file> windows.inf` command shows information related to the Windows operating system profile extracted from the memory dump file. Here is some key information provided in the result:

- `Kernel Base`: The base address of the Windows operating system kernel.
- DTB`: The address of the memory descriptor table.
- Symbols`: The path to the JSON file containing kernel symbols.
- `Is64Bit`: Indicates whether the operating system is 64-bit.
- `IsPAE`: Indicates whether Physical Address Extension (PAE) is enabled.
- Major/Minor`: The major and minor version of the Windows operating system.
- MachineType`: The machine type (architecture) of the operating system.
- SystemTime: Windows operating system time and date.
- NtSystemRoot`: The path to the Windows system directory.
- NtProductType`: The Windows product type (e.g. NtProductWinNt).
- NtMajorVersion / NtMinorVersion`: The major and minor version of the Windows kernel.
- `PE MajorOperatingSystemVersion / PE MinorOperatingSystemVersion`: The major and minor version of the operating system in the PE (Portable Executable) file information.
- `PE Machine`: The type of machine (architecture) in the PE file information.
- `PE TimeDateStamp`: The time stamp of the PE file.

# Find the malicious process, its PID and infection vectors

To identify the malicious process responsible for encrypting the file, as well as the associated infection vectors, I use the "windows.malfind" module:
```bash
python3 vol.py -f fcsc.dmp windows.malfind > investigation/malfind.txt
```
The result of this command indicates the presence of three potentially malicious processes. Examining the information provided, I conclude that the process responsible for encryption uses XOR encryption instructions and corresponds to the `VBoxTray.exe` process with process ID (PID) 6424.
```c
Volatility 3 Framework 2.4.2
PID   Process           Start              VPN                  End                VPN          Tag   Protection  CommitCharge
PrivateMemory  File  output Hexdump  Disasm
5124  SearchApp.exe  0x1c895560000  0x1c8955c3fff  VadS  PAGE_EXECUTE_READWRITE  2  1  Disabled
e9 fb ff fd ef ff ff ff  ........
ff cc cc cc cc cc cc cc  ........
e9 eb 03 fe ef ff ff ff  ........
ff cc cc cc cc cc cc cc  ........
e9 db 0f fe ef ff ff ff  ........
ff cc cc cc cc cc cc cc  ........
e9 cb 17 fe ef ff ff ff  ........
ff cc cc cc cc cc cc cc  ........
0x1c895560000: jmp 0x1c885540000
6424  VBoxTray.exe  0x22d82840000  0x22d82871fff  VadS  PAGE_EXECUTE_READWRITE  50  1  Disabled
fc 48 89 ce 48 81 ec 00  .H..H...
20 00 00 48 83 e4 f0 e8  ...H....
cc 00 00 00 41 51 41 50  ....AQAP
52 48 31 d2 51 56 65 48  RH1.QVeH
8b 52 60 48 8b 52 18 48  .R`H.R.H
8b 52 20 48 0f b7 4a 4a  .R.H..JJ
48 8b 72 50 4d 31 c9 48  H.rPM1.H
31 c0 ac 3c 61 7c 02 2c  1..<a|.,
0x22d82840000: cld
0x22d82840001: mov rsi, rcx
0x22d82840004: sub rsp, 0x2000
0x22d8284000b: and rsp, 0xfffffffffffffff0
0x22d8284000f: call 0x22d828400e0
0x22d82840014: push r9
0x22d82840016: push r8
0x22d82840018: push rdx
0x22d82840019: xor rdx, rdx
0x22d8284001c: push rcx
0x22d8284001d: push rsi
0x22d8284001e: mov rdx, qword ptr gs:[rdx + 0x60]
0x22d82840023: mov rdx, qword ptr [rdx + 0x18]
0x22d82840027: mov rdx, qword ptr [rdx + 0x20]
0x22d8284002b: movzx rcx, word ptr [rdx + 0x4a]
0x22d82840030: mov rsi, qword ptr [rdx + 0x50]
0x22d82840034: xor r9, r9
0x22d82840037: xor rax, rax
0x22d8284003a: lodsb al, byte ptr [rsi]
0x22d8284003b: cmp al, 0x61
0x22d8284003d: jl 0x22d82840041
2328  smartscreen.ex  0x193a0800000  0x193a081ffff  VadS  PAGE_EXECUTE_READWRITE  1  1  Disabled
48 89 54 24 10 48 89 4c  H.T$.H.L
24 08 4c 89 44 24 18 4c  $.L.D$.L
89 4c 24 20 48 8b 41 28  .L$.H.A(
48 8b 48 08 48 8b 51 50  H.H.H.QP
48 83 e2 f8 48 8b ca 48  H...H..H
b8 60 00 80 a0 93 01 00  .`......
00 48 2b c8 48 81 f9 70  .H+.H..p
0f 00 00 76 09 48 c7 c1  ...v.H..
0x193a0800000: mov qword ptr [rsp + 0x10], rdx
0x193a0800005: mov qword ptr [rsp + 8], rcx
0x193a080000a: mov qword ptr [rsp + 0x18], r8
0x193a080000f: mov qword ptr [rsp + 0x20], r9
0x193a0800014: mov rax, qword ptr [rcx + 0x28]
0x193a0800018: mov rcx, qword ptr [rax + 8]
0x193a080001c: mov rdx, qword ptr [rcx + 0x50]
0x193a0800020: and rdx, 0xfffffffffffffff8
0x193a0800024: mov rcx, rdx
0x193a0800027: movabs rax, 0x193a0800060
0x193a0800031: sub rcx, rax
0x193a0800034: cmp rcx, 0xf70
0x193a080003b: jbe 0x193a0800046
```
To find the parent and child processes of PID 6424 (VBoxTray.exe), I use the following command:
```bash
python3 vol.py -f fcsc.dmp
windows.pstree.PsTree --pid=5540 >
investigation/pstree_pid_5540.txt
```

The malicious process is found: "svchost.exe".
```
Volatility 3 Framework 2.4.2
PID PPID ImageFileName Offset(V) Threads Handles SessionId
Wow64 CreateTime ExitTime
624 548 winlogon.exe 0x818684cd7080 5 - 1
False 2023-04-16 21:46:21.000000 N/A
* 3892 624 userinit.exe 0x8186813f5340 0 - 1
False 2023-04-16 21:47:17.000000 2023-04-16 21:47:42.000000
** 3928 3892 explorer.exe 0x818684aa0340 66 - 1
False 2023-04-16 21:47:17.000000 N/A
*** 6424 3928 VBoxTray.exe 0x81868852e080 13 - 1
False 2023-04-16 21:47:34.000000 N/A
**** 5540 6424 svchost.exe 0x818687754080 1 - 1
False 2023-04-17 17:21:18.000000 N/A
```

To find out where the malicious "svchost.exe" process started from, I run the `windows.cmdline` module:
```bash
python3 vol.py -f fcsc.dmp windows.cmdline --pid=5540 > investigation/cmdline_pid_5540.txt
``````bash
Volatility 3 Framework 2.4.2
PID Process Args
5540 svchost.exe C:\Windows\Temp\svchost.exe
```

The latter tells us that the malicious process "svchost.exe" was executed from the path `C:\Windows\Temp\svchost.exe`. This confirms our analysis.

Finally, to find out which DLL the process used, I use the `windows.dlllist` module:
```bash
python3 vol.py -f fcsc.dmp
windows.dlllist --pid=5540 >
investigation/dlllist_pid_5540.txt
```

![dlllist](/Pictures/dlllist.png)

By examining these DLLs, we can identify the specific encryption functions that have been used:
- bcrypt.dll
- bcryptprimitive.dll

In conclusion, my investigation revealed the presence of the malicious process `svchost.exe` with PID `5540`. This process was executed from the location `C:\Windows\Temp\svchost.exe`. Further analysis of this PID's parent and child processes revealed its relationship with the `VBoxTray.exe` process (PID `6424`) as a vunerability vector.
- Vector :
    - Name: VBoxTray.exe
    - PID: 6424
    - Parent PID: 3928
- Ransomware :
    - Name: svchost.exe
    - PID: 5540
    - Parent PID: 6424

# Find the encrypted file

In order to find the encrypted file and recover it in clear text, we'll perform the following steps:

First, a file analysis using the Volatility tool on the memory dump :
```bash
python3 vol.py -f fcsc.dmp windows.filescan > investigation/filescan.txt
```
```c
0x818684ee8160 \Windows\System32\NPSMDesktopProvider.dll 216
0x818686c595a0 \Windows\System32\DispBroker.Desktop.dll 216
0x81868790a9d0 \Windows\System32\DesktopShellExt.dll 216
0x818687ecd680 \Windows\System32\DdcComImplementationsDesktop.dll 216
0x818687ed5ce0 \Windows\System32\SettingsEnvironment.Desktop.dll 216
0x818687ee9ec0 \Windows\System32\Windows.Cortana.Desktop.dll 216
0x818688458e50 \Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-
00C04FC295EE}\Microsoft-Windows-Client-Desktop-Required-
Package01~31bf3856ad364e35~amd64~~10.0.19041.2006.cat 216
0x818688a53c00 \Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-
00C04FC295EE}\Microsoft-Windows-Client-Desktop-Required-
Package05110~31bf3856ad364e35~amd64~~10.0.19041.2728.cat 216
0x818689b077d0 \Users\Admin\Desktop\th (9).webp 216
0x818689b0d270 \Users\Public\Desktop\desktop.ini 216
0x818689b0fca0 \Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-
00C04FC295EE}\Microsoft-Windows-Client-Desktop-Required-
Package051021~31bf3856ad364e35~amd64~~10.0.19041.2006.cat 216
0x818689b87700 \Users\Admin\Desktop\Microsoft Edge.lnk 216
0x818689b8b260 \Users\Admin\Desktop\desktop.ini 216
0x818689b8f590 \Users\Admin\Desktop 216
0x818689b9cba0 \Users\Public\Desktop 216
0x818689b9d1e0 \Users\Admin\Desktop 216
0x818689b9e4a0 \Users\Admin\Desktop 216
0x818689b9fda0 \Users\Public\Desktop 216
```
I found:
```c
0x818689b077d0 \Users\Admin\Desktop\th (9).webp 216
```

This path corresponds to the location of the file on the desktop. It's a file named "th (9).webp". I checked what the handles contain (to track resources opened by the process, including files):
```bash
python3 vol.py -f fcsc.dmp
windows.handles --pid=5540 >
investigation/handles_pid_5540.txt
```
```bash
cat handles_pid_5540.txt | grep "Admin | "grep "Desktop"
5540 svchost.exe 0x818689b8f590 0x218 File 0x100001
\Device\HarddiskVolume2\Users\Admin\Desktop
```

By examining the MFT table, I obtained a complete list of the files present on the system. I extracted information such as file names, locations, creation and modification dates, as well as the attributes associated with each file.

Using the `grep` command, I filtered the results according to the extension identified earlier (webp). This identified the file "th.webp" and provided access to important metadata such as its date and time. This information provides additional clues about the encrypted file and its use by the malicious process.

![MFT](/Pictures/MFT.png)

You can see the different copies of the file.
To obtain readable character sequences and target a potential flag file, I used the `strings` command, which extracts the strings present in the file. Then I filtered the results using the `grep` command to search for the presence of the keyword "flag".
```bash
strings fcsc.dmp >
investigation/strings.txt
grep "flag" strings.tx
...
flag.fcsc.enc
...
```

From the MFT table, I've used the `grep -A 15` command to search for information related to the "flag.fcsc.enc" file we identified earlier.

The result of the command shows several important details about this file. We can see that the file "flag.fcsc.enc" is located in the "Users\Admin\Desktop" directory. It is associated with the "$DATA" attribute and is followed by a sequence of hexadecimal data representing its contents.

Further analysis of the results reveals that the MFT entry corresponding to this file was found at offset 0x1327800. 
```c
cat mftparser_vol2.txt | grep -i -A 15 "flag.fcsc"
2023-04-17 17:23:45 UTC+0000 2023-04-17 17:23:50 UTC+0000 2023-04-17
17:23:50 UTC+0000 2023-04-17 17:23:50 UTC+0000
Users\Admin\Desktop\flag.fcsc.enc
$DATA
0000000000: 3b 65 17 19 64 03 71 9f dd 1a 30 ec 37 ba 83 c9
;e..d.q...0.7...
0000000010: 1b b0 44 c9 8d 05 45 88 ff 41 40 d6 32 e5 61 09
..D...E..A@.2.a.
0000000020: 5f f2 32 07 44 6a 8d 05 c7 fe 82 2f 22 76 9a 08
_.2.Dj...../"v..
0000000030: 32 28 7a ad ff 90 c8 4d 96 ca 99 54 1c 2c 58 f7
2(z....M...T.,X.
0000000040: 7a 8b e5 c5 5d 51 5a z...]QZ
***************************************************************************
***************************************************************************
MFT entry found at offset 0x1327800
Attribute: In Use & File
Record Number: 96166
Link count: 1
```
After searching the MFT table with the command `grep -i "mscmdrun"`, I found several entries corresponding to MsCmdRun log files. Among these entries, the one we're interested in is the file "WindowsTempMsCmdRun14.log".

This entry was created at the same date and time as the "flag.fcsc.enc" file we identified earlier. It is therefore highly likely that there is a correlation between these two files.
```c
cat mftparser_vol2.txt | grep -i "mscmdrun"
2023-04-17 17:22:03 UTC+0000 2023-04-17 17:22:03 UTC+0000 2023-04-17
17:22:03 UTC+0000 2023-04-17 17:22:03 UTC+0000
Windows\Temp\MsCmdRun3.log
2023-04-17 17:23:31 UTC+0000 2023-04-17 17:23:31 UTC+0000 2023-04-17
17:23:31 UTC+0000 2023-04-17 17:23:31 UTC+0000
Windows\Temp\MsCmdRun11.log
2023-04-17 17:23:57 UTC+0000 2023-04-17 17:23:57 UTC+0000 2023-04-17
17:23:57 UTC+0000 2023-04-17 17:23:57 UTC+0000
Windows\Temp\MsCmdRun15.log
2023-04-17 17:24:13 UTC+0000 2023-04-17 17:24:13 UTC+0000 2023-04-17
17:24:13 UTC+0000 2023-04-17 17:24:13 UTC+0000
Windows\Temp\MsCmdRun17.log
2023-04-17 17:22:45 UTC+0000 2023-04-17 17:22:45 UTC+0000 2023-04-17
17:22:45 UTC+0000 2023-04-17 17:22:45 UTC+0000
Windows\Temp\MsCmdRun6.log
2023-04-17 17:21:48 UTC+0000 2023-04-17 17:21:48 UTC+0000 2023-04-17
17:21:48 UTC+0000 2023-04-17 17:21:48 UTC+0000
Windows\Temp\MsCmdRun2.log
2023-04-17 17:22:56 UTC+0000 2023-04-17 17:22:56 UTC+0000 2023-04-17
17:22:56 UTC+0000 2023-04-17 17:22:56 UTC+0000
Windows\Temp\MsCmdRun7.log
2023-04-17 17:23:06 UTC+0000 2023-04-17 17:23:06 UTC+0000 2023-04-17
17:23:06 UTC+0000 2023-04-17 17:23:06 UTC+0000
Windows\Temp\MsCmdRun8.log
2023-04-17 17:23:38 UTC+0000 2023-04-17 17:23:38 UTC+0000 2023-04-17
17:23:38 UTC+0000 2023-04-17 17:23:38 UTC+0000
Windows\Temp\MsCmdRun12.log
2023-04-17 17:24:32 UTC+0000 2023-04-17 17:24:32 UTC+0000 2023-04-17
17:24:32 UTC+0000 2023-04-17 17:24:32 UTC+0000
Windows\Temp\MsCmdRun19.log
2023-04-17 17:23:44 UTC+0000 2023-04-17 17:23:44 UTC+0000 2023-04-17
17:23:44 UTC+0000 2023-04-17 17:23:44 UTC+0000
Windows\Temp\MsCmdRun13.log
2023-04-17 17:23:50 UTC+0000 2023-04-17 17:23:50 UTC+0000 2023-04-17
17:23:50 UTC+0000 2023-04-17 17:23:50 UTC+0000
Windows\Temp\MsCmdRun14.log
2023-04-17 17:21:18 UTC+0000 2023-04-17 17:21:18 UTC+0000 2023-04-17
17:21:18 UTC+0000 2023-04-17 17:21:18 UTC+0000
Windows\Temp\MsCmdRun0.log
2023-04-17 17:24:43 UTC+0000 2023-04-17 17:24:43 UTC+0000 2023-04-17
17:24:43 UTC+0000 2023-04-17 17:24:43 UTC+0000
Windows\Temp\MsCmdRun20.log
2023-04-17 17:23:15 UTC+0000 2023-04-17 17:23:15 UTC+0000 2023-04-17
17:23:15 UTC+0000 2023-04-17 17:23:15 UTC+0000
Windows\Temp\MsCmdRun9.log
2023-04-17 17:24:22 UTC+0000 2023-04-17 17:24:22 UTC+0000 2023-04-17
17:24:22 UTC+0000 2023-04-17 17:24:22 UTC+0000
Windows\Temp\MsCmdRun18.log
2023-04-17 17:22:18 UTC+0000 2023-04-17 17:22:18 UTC+0000 2023-04-17
17:22:18 UTC+0000 2023-04-17 17:22:18 UTC+0000
Windows\Temp\MsCmdRun4.log
2023-04-17 17:21:33 UTC+0000 2023-04-17 17:21:33 UTC+0000 2023-04-17
17:21:33 UTC+0000 2023-04-17 17:21:33 UTC+0000
Windows\Temp\MsCmdRun1.log
2023-04-17 17:22:32 UTC+0000 2023-04-17 17:22:32 UTC+0000 2023-04-17
17:22:32 UTC+0000 2023-04-17 17:22:32 UTC+0000
Windows\Temp\MsCmdRun5.log
2023-04-17 17:24:04 UTC+0000 2023-04-17 17:24:04 UTC+0000 2023-04-17
17:24:04 UTC+0000 2023-04-17 17:24:04 UTC+0000
Windows\Temp\MsCmdRun16.log
2023-04-17 17:23:24 UTC+0000 2023-04-17 17:23:24 UTC+0000 2023-04-17
17:23:24 UTC+0000 2023-04-17 17:23:24 UTC+0000
Windows\Temp\MsCmdRun10.log
```
```c
cat mftparser_vol2.txt | grep -i -A 15 "MsCmdRun14.log"
2023-04-17 17:23:50 UTC+0000 2023-04-17 17:23:50 UTC+0000 2023-04-17
17:23:50 UTC+0000 2023-04-17 17:23:50 UTC+0000
Windows\Temp\MsCmdRun14.log
$DATA
0000000000: 73 28 4a 54 11 3a 48 a7 b5 26 0b 86 01 85 bc a5
s(JT.:H..&......
0000000010: 73 87 2b a4 b1 3d 79 b7 c5 7c 2a e8 5a da 09 66
s.+..=y..|*.Z..f
0000000020: 68 cb 5f 3a 72 56 e5 3c ab c5 b5 16 1e 49 a6 37 h._:rV.
<.....I.7
0000000030: 5e 15 43 c7 c1 ad f0 72 fb f3 f3 6d 73 46 67 9b
^.C....r...msFg.
0000000040: 46 b2 db fc 6a 22 5e 89 8e 58 7d 0b 5c e5 4a d8
F...j"^..X}.\.J.
0000000050: 62 58 72 87 ee 36 f5 44 49 55 0f bd c0 00 e1 58
bXr..6.DIU.....X
0000000060: 60 5f 1e 0f `_..
***************************************************************************
***************************************************************************
MFT entry found at offset 0x45022400
Attribute: In Use & File
Record Number: 106393
```

At this stage, I've managed to recover the file containing the flag as well as the log file MsCmdRun14.log. All that remained was to decode and decrypt the flag in CyberChef using XOR encoding and encryption functions.

![CyberChef-1](/Pictures/CyberChef-1.png)

And here's the flag!

![CyberChef-2](/Pictures/CyberChef-2.png)
