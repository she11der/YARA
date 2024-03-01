rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Doejocrypt
{
	meta:
		description = "Detects files referencing identities associated with DoejoCrypt ransomware"
		author = "ditekShen"
		id = "bdf67fd3-8614-52f0-8804-9905f067a848"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L204-L213"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "b76996ef413d017fa571115f7331154c808fed0f1b1e0c97241cadbbef260a00"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "konedieyp@airmail.cc" ascii wide nocase
		$s2 = "uenwonken@memail.com" ascii wide nocase

	condition:
		any of them
}
