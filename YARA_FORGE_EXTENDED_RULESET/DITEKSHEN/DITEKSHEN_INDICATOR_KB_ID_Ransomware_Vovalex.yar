rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Vovalex
{
	meta:
		description = "Detects files referencing identities associated with Vovalex ransomware"
		author = "ditekShen"
		id = "95e9ddce-8a19-59f1-baf4-bdac61c9c396"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L184-L192"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0e8b426e55c1efaf59e5f255f1da9cdfbb509561d3f7ea5baa2815c3131866eb"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "vovanandlexus@cock.li" ascii wide nocase

	condition:
		any of them
}
