rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Ranzylocker
{
	meta:
		description = "Detects files referencing identities associated with RanzyLocker ransomware"
		author = "ditekShen"
		id = "33478dc4-c0ec-5cc8-8620-79e770f6a773"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L354-L363"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dc345257a3cca82a95e20505c94e90d8ac42240e1491ea1f34be121871673e26"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "eviluser@tutanota.com" ascii wide nocase
		$s2 = "evilpr0ton@protonmail.com" ascii wide nocase

	condition:
		any of them
}
