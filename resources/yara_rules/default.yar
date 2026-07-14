/*
 * ForensicToolkit — Built-in YARA Rules
 * Default ruleset covering common malware patterns, suspicious scripts,
 * and forensic indicators of compromise.
 */

rule Mimikatz_Strings
{
    meta:
        description = "Detects Mimikatz credential dumping tool"
        author      = "ForensicToolkit"
        threat_level = "critical"
        family      = "CredentialTheft"
        tags        = "mimikatz,credential,dumping"

    strings:
        $s1 = "mimikatz"        nocase
        $s2 = "sekurlsa"        nocase
        $s3 = "lsadump"         nocase
        $s4 = "kerberos::list"  nocase
        $s5 = "privilege::debug" nocase
        $hex1 = { 6D 69 6D 69 6B 61 74 7A }

    condition:
        any of them
}

rule Meterpreter_Payload
{
    meta:
        description = "Detects Metasploit Meterpreter shellcode patterns"
        author      = "ForensicToolkit"
        threat_level = "critical"
        family      = "Meterpreter"

    strings:
        $s1 = "meterpreter"       nocase
        $s2 = "ReflectiveDll"     nocase
        $s3 = "metsrv"            nocase
        $hex1 = { FC E8 82 00 00 00 }
        $hex2 = { FC E8 89 00 00 00 60 }

    condition:
        any of them
}

rule Suspicious_PowerShell
{
    meta:
        description = "Detects obfuscated or malicious PowerShell commands"
        author      = "ForensicToolkit"
        threat_level = "high"
        family      = "Obfuscation"

    strings:
        $s1 = "IEX"                              nocase
        $s2 = "Invoke-Expression"                nocase
        $s3 = "FromBase64String"                 nocase
        $s4 = "-EncodedCommand"                  nocase
        $s5 = "-WindowStyle Hidden"              nocase
        $s6 = "DownloadString"                   nocase
        $s7 = "Invoke-WebRequest"                nocase
        $s8 = "Net.WebClient"                    nocase
        $s9 = "bypass"                           nocase

    condition:
        3 of them
}

rule Ransomware_Indicators
{
    meta:
        description = "Detects common ransomware behavioral strings"
        author      = "ForensicToolkit"
        threat_level = "critical"
        family      = "Ransomware"

    strings:
        $s1 = "YOUR FILES ARE ENCRYPTED"   nocase
        $s2 = "bitcoin"                    nocase
        $s3 = ".locked"                    nocase
        $s4 = "READ_ME"                    nocase
        $s5 = "decrypt"                    nocase
        $s6 = "ransom"                     nocase
        $s7 = "CryptEncrypt"               nocase
        $s8 = "CryptoAPI"                  nocase
        $hex1 = { 52 41 4E 53 4F 4D }

    condition:
        3 of them
}

rule Webshell_PHP
{
    meta:
        description = "Detects PHP webshell patterns"
        author      = "ForensicToolkit"
        threat_level = "high"
        family      = "Webshell"

    strings:
        $s1 = "eval(base64_decode"   nocase
        $s2 = "system($_GET"         nocase
        $s3 = "passthru($_POST"      nocase
        $s4 = "exec($_REQUEST"       nocase
        $s5 = "shell_exec("          nocase
        $s6 = "<?php @eval"          nocase

    condition:
        any of them
}

rule Suspicious_Registry_Keys
{
    meta:
        description = "Detects strings associated with registry-based persistence"
        author      = "ForensicToolkit"
        threat_level = "medium"
        family      = "Persistence"

    strings:
        $s1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        $s3 = "SYSTEM\\CurrentControlSet\\Services"
        $s4 = "CurrentVersion\\RunOnce"

    condition:
        any of them
}

rule Network_Backdoor_Strings
{
    meta:
        description = "Detects strings associated with network backdoors"
        author      = "ForensicToolkit"
        threat_level = "high"
        family      = "Backdoor"

    strings:
        $s1 = "reverse shell"      nocase
        $s2 = "bind shell"         nocase
        $s3 = "netcat"             nocase
        $s4 = "ncat"               nocase
        $s5 = "nc.exe"             nocase
        $s6 = "socat"              nocase
        $s7 = "cmd.exe /c"         nocase
        $hex1 = { 2F 62 69 6E 2F 73 68 }

    condition:
        2 of them
}

rule Credential_Harvesting
{
    meta:
        description = "Detects credential harvesting tool signatures"
        author      = "ForensicToolkit"
        threat_level = "high"
        family      = "CredentialTheft"

    strings:
        $s1 = "HashedPassword"      nocase
        $s2 = "NTLMv2"             nocase
        $s3 = "SAM database"        nocase
        $s4 = "password hash"       nocase
        $s5 = "pwdump"              nocase
        $s6 = "fgdump"              nocase
        $s7 = "LaZagne"             nocase

    condition:
        any of them
}

rule Packed_Executable
{
    meta:
        description = "Detects common executable packers (UPX, ASPack, etc.)"
        author      = "ForensicToolkit"
        threat_level = "medium"
        family      = "Packed"

    strings:
        $upx1  = "UPX0"
        $upx2  = "UPX1"
        $upx3  = "UPX!"
        $asp1  = "ASPack"
        $nspack = "NsPack"
        $pex   = ".petite"

    condition:
        any of them
}

rule Suspicious_Document_Macro
{
    meta:
        description = "Detects suspicious Office macro patterns"
        author      = "ForensicToolkit"
        threat_level = "high"
        family      = "MacroMalware"

    strings:
        $s1 = "AutoOpen"           nocase
        $s2 = "Document_Open"      nocase
        $s3 = "Shell("             nocase
        $s4 = "WScript.Shell"      nocase
        $s5 = "CreateObject"       nocase
        $s6 = "MSXML2.XMLHTTP"     nocase
        $s7 = "powershell"         nocase

    condition:
        3 of them
}
