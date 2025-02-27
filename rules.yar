// YARA Rules File
// Author: Valan
// Description: A collection of YARA rules for detecting various types of malicious files and behaviors.

rule EICAR_Test_File {
    meta:
        author = "Valan"
        description = "Detects the EICAR antivirus test file."
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "Low"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase
    condition:
        $eicar
}

rule Suspicious_PowerShell_Script {
    meta:
        author = "Valan"
        description = "Detects suspicious PowerShell scripts."
        severity = "High"
        reference = "https://docs.microsoft.com/en-us/powershell/"
    strings:
        $download_cradle = /Invoke-WebRequest\s+-Uri\s+['"]http[s]?:\/\// nocase
        $bypass_amsi = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)" nocase
        $encoded_command = "-EncodedCommand" nocase
    condition:
        2 of ($download_cradle, $bypass_amsi, $encoded_command)
}

rule Office_Macro_Malware {
    meta:
        author = "Valan"
        description = "Detects malicious Office macros."
        severity = "High"
        reference = "https://docs.microsoft.com/en-us/office/vba/api/overview/"
    strings:
        $auto_open = "Sub AutoOpen()" nocase
        $shell_exec = "Shell(" nocase
        $powershell = "powershell" nocase
    condition:
        $auto_open and any of ($shell_exec, $powershell)
}

rule JavaScript_Downloader {
    meta:
        author = "Valan"
        description = "Detects JavaScript downloaders."
        severity = "High"
        reference = "https://developer.mozilla.org/en-US/docs/Web/JavaScript"
    strings:
        $wscript_shell = "WScript.Shell" nocase
        $xmlhttp = "XMLHttpRequest" nocase
        $adodb_stream = "ADODB.Stream" nocase
    condition:
        any of ($wscript_shell, $xmlhttp, $adodb_stream)
}

rule Linux_Persistence {
    meta:
        author = "Valan"
        description = "Detects Linux persistence mechanisms."
        severity = "High"
        reference = "https://linux.die.net/man/"
    strings:
        $cron_job = /@reboot.{,100}\/path\/to\/malicious_script\.sh/i
        $rc_local = "/etc/rc.local" nocase
        $systemd_service = "/etc/systemd/system/" nocase
    condition:
        any of ($cron_job, $rc_local, $systemd_service)
}

rule Obfuscated_Batch_File {
    meta:
        author = "Valan"
        description = "Detects obfuscated batch files."
        severity = "Medium"
        reference = "https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/cmd"
    strings:
        $cmd_exe = "cmd.exe" nocase
        $powershell = "powershell.exe" nocase
      
    condition:
        any of ($cmd_exe ,$powershell) 
}

rule Persistence_Mechanisms {
    meta:
        author = "Valan"
        description = "Detects common persistence techniques in scripts and binaries."
        severity = "High"
    strings:
        $registry_run = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $cron_job = /@(reboot|daily|hourly).{,100}python/i
        $startup_folder = /AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/ wide
    condition:
        any of ($registry_run, $cron_job, $startup_folder)
}

rule Suspicious_ELF_File {
    meta:
        author = "Valan"
        description = "Detects suspicious ELF files."
        severity = "High"
        reference = "https://en.wikipedia.org/wiki/Executable_and_Linkable_Format"
    strings:
        $elf_magic = { 7F 45 4C 46 }  // ELF magic number
        $ptrace = "ptrace" nocase
        $inet_addr = "inet_addr" nocase
    condition:
        $elf_magic at 0 and any of ($ptrace, $inet_addr)
}

rule Suspicious_ZIP_File {
    meta:
        author = "Valan"
        description = "Detects ZIP files containing executables or scripts."
        severity = "Medium"
        reference = "https://en.wikipedia.org/wiki/ZIP_(file_format)"
    strings:
        $zip_magic = { 50 4B 03 04 }  // ZIP file magic number
        $exe_file = ".exe" wide
        $script_file = /\.(vbs|js|bat|ps1)/ wide
    condition:
        $zip_magic at 0 and any of ($exe_file, $script_file)
}

rule Common_Shellcode {
    meta:
        author = "Valan"
        description = "Detects common shellcode patterns, including encoded variants."
        severity = "High"
        reference = "https://github.com/Yara-Rules/rules/blob/master/malware/Common_Shellcode.yar"
    strings:
        $exec_shell = { 31 C0 (50|68) [4] 68 2F 62 69 6E }
        $windows_stager = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B C4 6A ?? 50 6A ?? 8B E0 }
    condition:
        any of ($exec_shell, $windows_stager)
}

rule Obfuscation_Detection {
    meta:
        author = "Valan"
        description = "Detects common obfuscation patterns and methods."
        severity = "Medium"
        reference = "https://github.com/Yara-Rules/rules/blob/master/packers/Obfuscation_Detection.yar"
    strings:
        $base64 = "base64.b64decode" nocase
        $rot13 = "rot13" nocase
        $eval = "eval" nocase
        $exec = "exec" nocase
        $zlib = "zlib.decompress" nocase
        $hex_strings = /\\x[0-9a-f]{2}/ wide
    condition:
        (2 of ($base64, $rot13, $zlib, $hex_strings)) or ($eval and $exec)
}

rule Locky_Ransomware {
    meta:
        description = "Detects Locky Ransomware"
        author = "Valan"
        date = "2025-02-13"
    strings:
        $locky1 = "locky@princeofwales.com" wide ascii
        $locky2 = "!!! IMPORTANT INFORMATION !!!"
        $locky3 = "RSA-2048" wide ascii
    condition:
        any of them
}



