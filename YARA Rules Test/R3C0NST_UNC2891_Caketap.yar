rule R3C0NST_UNC2891_Caketap
{
	meta:
		description = "Detects UNC2891 Rootkit Caketap"
		author = "Frank Boldewin (@r3c0nst)"
		id = "9c2ffe3d-69ca-5f93-bdb1-40e449139dec"
		date = "2022-03-30"
		modified = "2023-01-05"
		reference = "https://github.com/fboldewin/YARA-rules/"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/UNC2891_Caketap.yar#L1-L16"
		license_url = "N/A"
		logic_hash = "530a7d062a218217d2c05460428b2576c3fe2a6099c93940aabde73c513a8914"
		score = 75
		quality = 88
		tags = ""

	strings:
		$str1 = ".caahGss187" ascii fullword
		$str2 = "ipstat" ascii
		$code1 = {41 80 7E 06 4B 75 ?? 41 80 7E 07 57 75 ?? 41 0F B6 46 2B}
		$code2 = {41 C6 46 01 3D 41 C6 46 08 32}

	condition:
		uint32(0)==0x464c457f and ( all of ($code*) or ( all of ($str*) and #str2==2))
}