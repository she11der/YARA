rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Unlockyourfiles
{
	meta:
		description = "Detects files referencing identities associated with UnlockYourFiles ransomware"
		author = "ditekShen"
		id = "fdc3ec49-66cc-5a0b-87a6-3660dd6f3b72"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L279-L288"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a33dae7f08eb0c2415fbfdadf2cbbf90c68bc802352277422c6d0a2dbd62cd82"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "4lok3r@tutanota.com" ascii wide nocase
		$s2 = "4lok3r@protonmail.com" ascii wide nocase

	condition:
		any of them
}
