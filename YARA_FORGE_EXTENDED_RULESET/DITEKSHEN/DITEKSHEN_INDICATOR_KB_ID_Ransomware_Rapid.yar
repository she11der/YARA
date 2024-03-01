rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Rapid
{
	meta:
		description = "Detects files referencing identities associated with Rapid ransomware"
		author = "ditekShen"
		id = "a1c6f3c0-2fec-5d96-9965-8129a843ae90"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L428-L436"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ea82a3fcb1d836e1c250e9a576064e1babdb82b4970555260af2eb68726cfd16"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "jimmyneytron@tuta.io" ascii wide nocase

	condition:
		any of them
}
