rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Rhysida
{
	meta:
		description = "Detects files referencing identities associated with Rhysida ransomware"
		author = "ditekShen"
		id = "7ee0fb41-9267-5b65-ada3-229f2e390da6"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L1688-L1697"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e3e07bab2982a30a5372e6708ede6707d132d410aa5b5b1a29bdb5d06910a88e"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "SethZemlak@onionmail.org" ascii wide nocase
		$s2 = "JacquieKunze@onionmail.org" ascii wide nocase

	condition:
		any of them
}
