rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Jobcryptor
{
	meta:
		description = "Detects files referencing identities associated with JobCryptor ransomware"
		author = "ditekShen"
		id = "406f5638-883b-57a4-a2ba-532d2bd3ae83"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L237-L247"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c8c5dcc0d7484a3ac6e702cca8bd0907f9e4f4aea5e99c4c3f988389e0d803a7"
		score = 75
		quality = 69
		tags = ""

	strings:
		$s1 = "olaggoune235@protonmail.ch" ascii wide nocase
		$s2 = "ouardia11@tutanota.com" ascii wide nocase
		$s3 = "laggouneo11@gmail.com" ascii wide nocase

	condition:
		any of them
}
