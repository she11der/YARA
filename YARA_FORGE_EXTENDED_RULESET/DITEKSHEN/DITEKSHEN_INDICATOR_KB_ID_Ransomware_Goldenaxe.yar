rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Goldenaxe
{
	meta:
		description = "Detects files referencing identities associated with GoldenAxe ransomware"
		author = "ditekShen"
		id = "cd6486eb-742f-50fb-bd99-c5d778886477"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L82-L91"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2540da85880dc08b51a2d096cefd8ed3cb14ccd171b71b434ccf26e7c5f1b54b"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "xxback@keemail.me" nocase ascii wide
		$s2 = "darkusmbackup@protonmail.com" nocase ascii wide

	condition:
		any of them
}
