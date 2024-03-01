rule TRELLIX_ARC_STEALER_Emirates_Statement : STEALER
{
	meta:
		description = "Credentials Stealing Attack"
		author = "Christiaan Beek | McAfee ATR Team"
		id = "b5a6d996-8a3d-5238-95af-bf5ff893bbc5"
		date = "2013-06-30"
		modified = "2020-08-14"
		reference = "https://github.com/advanced-threat-research/Yara-Rules/"
		source_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/stealer/STEALER_EmiratesStatement.yar#L1-L24"
		license_url = "https://github.com/advanced-threat-research/Yara-Rules//blob/fc51a3fe3b450838614a5a5aa327c6bd8689cbb2/LICENSE"
		hash = "7cf757e0943b0a6598795156c156cb90feb7d87d4a22c01044499c4e1619ac57"
		logic_hash = "17eaddf375fc1875fb0275f8c0f93dfe921b452bdc6eb471adc155f749492328"
		score = 75
		quality = 45
		tags = "STEALER"
		rule_version = "v1"
		malware_type = "stealer"
		malware_family = "Stealer:W32/DarkSide"
		actor_type = "Cybercrime"
		actor_group = "Unknown"

	strings:
		$string0 = "msn.klm"
		$string1 = "wmsn.klm"
		$string2 = "bms.klm"

	condition:
		all of them
}
