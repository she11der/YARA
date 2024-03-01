rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Phobos
{
	meta:
		description = "Detects files referencing identities associated with Phobos ransomware"
		author = "ditekShen"
		id = "cee09220-4038-5190-b595-28f67c845588"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L152-L161"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "cf9e163d2315d465afb47bf83f30d5d27e14c4cbbc1c235dcb15b75fb509ba7d"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "helprecover@foxmail.com" ascii wide nocase
		$s2 = "recoverhelp2020@thesecure.biz" ascii wide nocase

	condition:
		any of them
}
