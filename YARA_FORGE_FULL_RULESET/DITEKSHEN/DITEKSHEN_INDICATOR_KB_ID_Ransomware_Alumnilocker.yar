rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Alumnilocker
{
	meta:
		description = "Detects files referencing identities associated with AlumniLocker ransomware"
		author = "ditekShen"
		id = "64b6aff8-3758-5837-b814-e2505a9c12a3"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L194-L202"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "aeab9cb2b2da246e1863cd1102d901d322017d0b309e852d83e4f66f6e4bdd22"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "alumnilocker@protonmail.com" ascii wide nocase

	condition:
		any of them
}
