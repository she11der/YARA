import "pe"

rule SIGNATURE_BASE_Powershell_Attack_Scripts
{
	meta:
		description = "Powershell Attack Scripts"
		author = "Florian Roth (Nextron Systems)"
		id = "e8c4a672-229b-56c8-811b-071ae9ff341e"
		date = "2016-03-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3157-L3172"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "42a52de089ee00e229499fea23b8acd0b7c881a9c578671aea180c0c018a54e0"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "PowershellMafia\\Invoke-Shellcode.ps1" ascii
		$s2 = "Nishang\\Do-Exfiltration.ps1" ascii
		$s3 = "PowershellMafia\\Invoke-Mimikatz.ps1" ascii
		$s4 = "Inveigh\\Inveigh.ps1" ascii

	condition:
		1 of them
}
