rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Epsilon
{
	meta:
		description = "Detects files referencing identities associated with Epsilon ransomware"
		author = "ditekShen"
		id = "acdeb3b1-872b-5892-9dfe-2e506f767da2"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L163-L171"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "163694ed2ae181764fc6e62027487d183114be35a689dd44d4d9761149df244b"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "neftet@tutanota.com" ascii wide nocase

	condition:
		any of them
}
