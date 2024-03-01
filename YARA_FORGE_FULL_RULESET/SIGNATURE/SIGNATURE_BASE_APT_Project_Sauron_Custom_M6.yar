rule SIGNATURE_BASE_APT_Project_Sauron_Custom_M6 : FILE
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "Florian Roth (Nextron Systems)"
		id = "1aa6dd43-52ac-5321-9941-767833073c37"
		date = "2016-08-09"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron_extras.yar#L208-L226"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "95ca9a0b2e71e7152d20a01d238e7362024c6dac6fc95ed2ebfa96dcbc8dbd40"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3782b63d7f6f688a5ccb1b72be89a6a98bb722218c9f22402709af97a41973c8"

	strings:
		$s1 = "rseceng.dll" fullword wide
		$s2 = "Remote Security Engine" fullword wide
		$op0 = { 8b 0d d5 1d 00 00 85 c9 0f 8e a2 }
		$op1 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 }
		$op2 = { 80 75 29 85 c9 79 25 b9 01 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and ( all of ($s*)) and 1 of ($op*)) or ( all of them )
}
