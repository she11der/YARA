rule SIGNATURE_BASE_Reveal_Memorycredentials : FILE
{
	meta:
		description = "Auto-generated rule - file Reveal-MemoryCredentials.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "ca06c702-45fe-5ab5-b53e-c3f7b7006570"
		date = "2015-08-31"
		modified = "2023-12-05"
		reference = "https://github.com/giMini/RWMC/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_rwmc_powershell_creddump.yar#L8-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "893c26818c424d0ff549c1fbfa11429f36eecd16ee69330c442c59a82ce6adea"
		logic_hash = "d740462aacd3b30d0258d018344642683fefd43ef033dd7f5bdde2bdddce4115"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$dumpAProcessPath = \"C:\\Windows\\temp\\msdsc.exe\"" fullword ascii
		$s2 = "$user = Get-ADUser -Filter {UserPrincipalName -like $loginPlainText -or sAMAccountName -like $loginPlainText}" fullword ascii
		$s3 = "Copy-Item -Path \"\\\\$computername\\\\c$\\windows\\temp\\lsass.dmp\" -Destination \"$logDirectoryPath\"" fullword ascii
		$s4 = "if($backupOperatorsFlag -eq \"true\") {$loginPlainText = $loginPlainText + \" = Backup Operators\"}            " fullword ascii

	condition:
		filesize <200KB and 1 of them
}
