rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Cuba
{
	meta:
		description = "Detects files referencing identities associated with JobCryptor ransomware"
		author = "ditekShen"
		id = "5eea027d-2164-54f2-a2bf-74b5d532e610"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L249-L261"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b734199c8593c338c803518b2729e9d9ceaaed5d21585a3d299885433d8f796e"
		score = 75
		quality = 65
		tags = ""

	strings:
		$s1 = "helpadmin2@protonmail.com" ascii wide nocase
		$s2 = "helpadmin2@cock.li" ascii wide nocase
		$s3 = "mfra@cock.li" ascii wide nocase
		$s4 = "admin@cuba-supp.com" ascii wide nocase
		$s5 = "cuba_support@exploit.im" ascii wide nocase

	condition:
		any of them
}
