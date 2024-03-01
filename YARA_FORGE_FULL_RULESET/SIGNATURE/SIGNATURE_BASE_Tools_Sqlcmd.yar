rule SIGNATURE_BASE_Tools_Sqlcmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file Sqlcmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "26e29826-d4bb-55d0-9331-a91e4473daca"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1409-L1428"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "99d56476e539750c599f76391d717c51c4955a33"
		logic_hash = "aa600f7c56d72d767e9ca51d8b1ee2b2c62302ea1afbed39e4670debd30c5247"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "[Usage]:  %s <HostName|IP> <UserName> <Password>" fullword ascii
		$s1 = "=============By uhhuhy(Feb 18,2003) - http://www.cnhonker.net=============" fullword ascii
		$s4 = "Cool! Connected to SQL server on %s successfully!" fullword ascii
		$s5 = "EXEC master..xp_cmdshell \"%s\"" fullword ascii
		$s6 = "=======================Sqlcmd v0.21 For HScan v1.20=======================" fullword ascii
		$s10 = "Error,exit!" fullword ascii
		$s11 = "Sqlcmd>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and 3 of them
}
