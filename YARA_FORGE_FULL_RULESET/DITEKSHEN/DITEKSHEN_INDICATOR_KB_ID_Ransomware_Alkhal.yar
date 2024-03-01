rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Alkhal
{
	meta:
		description = "Detects files referencing identities associated with AlKhal ransomware"
		author = "ditekShen"
		id = "32e14a6e-fc2e-5c0a-b8e3-33e219923d90"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L365-L374"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bd2d66a9cd33ab15b451158cd6c0e6579735653611ee2e6c8045a5807091938d"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "alkhal@tutanota.com" ascii wide nocase
		$s2 = "cyrilga@tutanota.com" ascii wide nocase

	condition:
		any of them
}
