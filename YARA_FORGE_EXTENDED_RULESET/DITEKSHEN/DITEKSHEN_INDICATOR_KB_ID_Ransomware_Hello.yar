rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Hello
{
	meta:
		description = "Detects files referencing identities associated with Hello / WickrMe ransomware"
		author = "ditekShen"
		id = "02bbaa61-7ea3-5edd-8b38-27ef1f6ee1e2"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L263-L277"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dfafb0323a50891c03c4b706d4f3a6a511cecdee2448c1f554b416ba1e3d3df9"
		score = 75
		quality = 61
		tags = ""

	strings:
		$s1 = "emming@tutanota.com" ascii wide nocase
		$s2 = "ampbel@protonmail.com" ascii wide nocase
		$s3 = "asauribe@tutanota.com" ascii wide nocase
		$s4 = "candietodd@tutanota.com" ascii wide nocase
		$s5 = "kellyreiff@tutanota.com" ascii wide nocase
		$s6 = "kevindeloach@protonmail.com" ascii wide nocase
		$s7 = "sheilabeasley@tutanota.com" ascii wide nocase

	condition:
		any of them
}
