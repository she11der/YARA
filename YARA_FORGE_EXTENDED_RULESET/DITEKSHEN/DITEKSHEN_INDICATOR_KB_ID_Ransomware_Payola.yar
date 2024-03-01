rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Payola
{
	meta:
		description = "Detects files referencing identities associated with Payola ransomware"
		author = "ditekShen"
		id = "7c1fc06b-fc71-5679-befd-686b2e05e3a4"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L1699-L1708"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "568141c03d14faef0cfc4f5fbdec45a5109a1ad5cbbe99e76a1db86e7ef4dc5d"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "pcsupport@skiff.com" ascii wide nocase
		$s2 = "pctalk01@tutanota.com" ascii wide nocase

	condition:
		any of them
}
