rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Zeoticus
{
	meta:
		description = "Detects files referencing identities associated with Zeoticus ransomware"
		author = "ditekShen"
		id = "4d5f0d6d-f792-563d-9a9b-1986f5af8743"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L226-L235"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7a83b15b0c8e81f67d11f8b5d9a43ba4e1e3a0f6741ddd0daafe4e742dd91cd8"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "anobtanium@tutanota.com" ascii wide nocase
		$s2 = "anobtanium@cock.li" ascii wide nocase

	condition:
		any of them
}
