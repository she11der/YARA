rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Buran
{
	meta:
		description = "Detects files referencing identities associated with Buran ransomware"
		author = "ditekShen"
		id = "63cdda3f-78ed-5ce5-a8e0-e0893f2c314e"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L125-L140"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "685126efa7f90ce296fc616bd8d5d89a5b4b9aba8b60601b29534de21a0d0015"
		score = 75
		quality = 59
		tags = ""

	strings:
		$s1 = "recovery_server@protonmail.com" ascii wide nocase
		$s2 = "recovery1server@cock.li" ascii wide nocase
		$s3 = "polssh1@protonmail.com" ascii wide nocase
		$s4 = "polssh@protonmail.com" ascii wide nocase
		$s5 = "buransupport@exploit.im" ascii wide nocase
		$s6 = "buransupport@xmpp.jp" ascii wide nocase
		$s7 = "jacksteam2018@protonmail.com" ascii wide nocase
		$s8 = "notesteam2018@tutanota.com" ascii wide nocase

	condition:
		any of them
}
