rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Ryuk
{
	meta:
		description = "Detects files referencing identities associated with Ryuk ransomware"
		author = "ditekShen"
		id = "00cf99da-ff3c-5c91-8966-69a8afc8613a"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L582-L592"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a2b6106fc49dd254ca936e285fa0c2a3aee7110832686638d20d369d77f6c48f"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "WayneEvenson@protonmail.com" ascii wide nocase
		$s2 = "WayneEvenson@tutanota.com" ascii wide nocase
		$s3 = "14hVKm7Ft2rxDBFTNkkRC3kGstMGp2A4hk" ascii wide

	condition:
		any of them
}
