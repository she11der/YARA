rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Lockdown
{
	meta:
		description = "Detects files referencing identities associated with LockDown / cantopen ransomware"
		author = "ditekShen"
		id = "603f0113-d77b-590c-b2a0-804c6d1fbfbc"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L594-L603"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "cb17bb92d6e8189a08508481b75d301a1227906815c684753859914d77d7b3e7"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "CCWhite@onionmail.org" ascii wide nocase
		$s2 = "bc1q6ug0vrxz66d564qznclu9yyyvn6zurskezmt64" ascii wide

	condition:
		any of them
}
