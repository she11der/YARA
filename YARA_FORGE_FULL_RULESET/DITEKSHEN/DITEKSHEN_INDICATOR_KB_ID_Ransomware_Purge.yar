rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Purge
{
	meta:
		description = "Detects files referencing identities associated with Purge ransomware"
		author = "ditekShen"
		id = "2a0f2c69-b179-5e48-9db6-be25e329f72b"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L215-L224"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "49f3f5a88212d4bed1f0237a4437fb537e84cd6dd26c5fe224250f3b6e39d384"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "rscl@dr.com" ascii wide nocase
		$s2 = "rscl@usa.com" ascii wide nocase

	condition:
		any of them
}
