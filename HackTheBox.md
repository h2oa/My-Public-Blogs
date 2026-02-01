# Easy

## Cap

Connect VPN `sudo openvpn --config machines_sg-1.ovpn`

<img width="1259" height="397" alt="{F43AA1F3-AA69-43C0-A4F3-9E5B9B34B87F}" src="https://github.com/user-attachments/assets/abb2a565-2d92-46d1-8967-fc04d359ad06" />

Check connection to the target machine:

<img width="1384" height="613" alt="{1F1D1C8C-98BF-4705-9ED0-24581EC3ACA9}" src="https://github.com/user-attachments/assets/210321ac-d47a-425d-ba45-a3f27bb642e0" />

Use `nmap` to find the open ports with TCP and UDP scan option (Some services only run with UDP protocols, sometimes TCP scan is not enough)

```
nmap -p- 10.129.21.223 --min-rate=2000
```

<img width="1019" height="343" alt="{7CCF8615-E4EA-495A-8742-0543A62B6351}" src="https://github.com/user-attachments/assets/6b82fe71-f184-436e-8fa7-ecbc604398da" />

<img width="1249" height="295" alt="{1187D784-9F61-4E78-AB36-27EB84805520}" src="https://github.com/user-attachments/assets/51b79ea2-f546-44e4-9e40-3b942c7a0a33" />

We got three open ports with TCP protocol:

```
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

Use `-sCV` flag for the version detection and some defaults script check: `nmap -p21,22,80 -sCV 10.129.21.223`

<img width="1324" height="653" alt="{4676A5A7-9363-4388-A8D9-B50C136A2B2E}" src="https://github.com/user-attachments/assets/70d7911b-2e47-4434-a2c1-6add24bcab22" />

Check the SSH service with root and empty password -> failed

<img width="1038" height="277" alt="{92B04CFF-CE83-47EB-9D8E-329AD9FED242}" src="https://github.com/user-attachments/assets/b36f2c77-cab0-4ab6-a0df-6c4566724eae" />

Check the FTP connect with anonymous -> failed

<img width="932" height="287" alt="{2F989A6E-5383-4B05-AD01-D3A990B207D1}" src="https://github.com/user-attachments/assets/408fd447-d46a-49d4-8415-fdda3cb44fff" />

Access to http://10.129.21.223, we can see a dashboard with default login as guest

<img width="1919" height="628" alt="{E2BE83A5-DB06-47DD-B6EE-93FF0C151344}" src="https://github.com/user-attachments/assets/f5047de5-0a74-4d90-810a-d9c4c722e17d" />

The settings feature displays the network package data and allows downloads. This guest account has no data

<img width="1507" height="617" alt="image" src="https://github.com/user-attachments/assets/9d486bb6-3ac8-4ee0-bc88-7350c5e47d6c" />

Endpoint `/data/1` caught my attention, change to `/data/0` we got a insecure direct object reference vulnerability here

<img width="1882" height="752" alt="{43E33E8D-C7CE-47D6-B4A5-DD28348B1AD0}" src="https://github.com/user-attachments/assets/8e81b505-1b61-4157-906e-d94e97955f45" />

Download and analyze with Wireshark, we can see a ftp login account with successful message `nathan:Buck3tH4TF0RM3!`

<img width="1341" height="458" alt="image" src="https://github.com/user-attachments/assets/5f9cf0ee-4ac0-4f54-a2a8-edf727b4c5f5" />

Try the ftp login, we have the user flag:

<img width="1879" height="737" alt="{1B0317CD-1EA2-4634-AA66-50687C929335}" src="https://github.com/user-attachments/assets/721fc7eb-017f-4b11-8e52-8c5987c14a32" />

We can also connect SSH with this ftp credential. Check the sudo rights permission `sudo -l` -> There is no command that this user can run with sudo permission

<img width="817" height="149" alt="{5C697078-02C4-4562-8F3D-87D5B9BD8A96}" src="https://github.com/user-attachments/assets/994ec911-1f2e-4941-9ef1-6bd9bfd808ac" />

Find all SUID files, and ignore all the error message (error will write to /dev/null): `find / -perm -u=s -type f 2>/dev/null`. These SUID files run with the owner's privileges (usually root) -> lead to privilege escalation

<img width="1132" height="373" alt="{FF334C75-9D34-405D-92A8-82088A80F050}" src="https://github.com/user-attachments/assets/0a525876-98d0-48ff-bc34-65260023f774" />

After searching, I found that `/usr/bin/pkexec` could lead to privilege escalation, refer to `https://github.com/ly4k/PwnKit`

<img width="1876" height="240" alt="{AA748F02-9DAE-41FB-BDC2-DC4667A05D3C}" src="https://github.com/user-attachments/assets/bcba1290-06e9-4f9e-b936-8a3abae07924" />

<img width="1120" height="247" alt="{D06B9BFC-A823-41B5-AA6E-6375715E0226}" src="https://github.com/user-attachments/assets/2defb1a5-6b0a-4ff5-bab2-e1cb96504f41" />

Official write up show another way to privilege escalation by linpeas `https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS`

<img width="1401" height="515" alt="{D17B9940-046F-4210-8005-D247FD057B76}" src="https://github.com/user-attachments/assets/86105298-ee63-4c07-b682-e72946c54d47" />

The below CVE appear in linpeas' result

<img width="1474" height="658" alt="{03B0455F-3D1D-4F72-8DA7-597498044641}" src="https://github.com/user-attachments/assets/d4f4aa2c-2595-4fd4-a703-2a90b2c04699" />

<img width="1138" height="186" alt="{E2292A95-D688-4E5F-8EB6-FA40FBEA0DFE}" src="https://github.com/user-attachments/assets/e4458a65-4842-426d-8137-cfe60b2793bd" />

Python 3.8 at `/usr/bin/python3.8` is found to have `cap_setuid` and `cap_net_bind_service`, which isn't the default setting

<img width="1434" height="321" alt="{75707BE4-EAE6-486F-9E78-A16F7B3AC313}" src="https://github.com/user-attachments/assets/2252ac46-a10b-428f-86cc-4020c93db5e8" />

<img width="1202" height="139" alt="{7CAED19A-93B3-4A95-B33A-DA7339F25104}" src="https://github.com/user-attachments/assets/2dc31ab4-6fac-46f4-952c-cd41ff1e1636" />

## 
