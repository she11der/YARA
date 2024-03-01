rule SIGNATURE_BASE_APT_Project_Sauron_Custom_M1 : FILE
{
	meta:
		description = "Detects malware from Project Sauron APT"
		author = "Florian Roth (Nextron Systems)"
		id = "c741bd7d-1885-55f1-a5b3-8f00fda2fe39"
		date = "2016-08-09"
		modified = "2023-12-05"
		reference = "https://goo.gl/eFoP4A"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_project_sauron_extras.yar#L130-L148"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c81c996e487bdd840111513724ccf1220ee3bd8280d776aa4c128ef5263ee136"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "9572624b6026311a0e122835bcd7200eca396802000d0777dba118afaaf9f2a9"

	strings:
		$s1 = "ncnfloc.dll" fullword wide
		$s4 = "Network Configuration Locator" fullword wide
		$op0 = { 80 75 6e 85 c0 79 6a 66 41 83 38 0a 75 63 0f b7 }
		$op1 = { 80 75 29 85 c9 79 25 b9 01 }
		$op2 = { 2b d8 48 89 7c 24 38 44 89 6c 24 40 83 c3 08 89 }

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and ( all of ($s*)) and 1 of ($op*)) or ( all of them )
}
