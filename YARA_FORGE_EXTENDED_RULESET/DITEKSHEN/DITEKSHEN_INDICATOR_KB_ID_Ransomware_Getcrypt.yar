rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Getcrypt
{
	meta:
		description = "Detects files referencing identities associated with GetCrypt ransomware"
		author = "ditekShen"
		id = "b5e31968-e626-5fbb-8bfe-942b48737367"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L93-L106"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "401f4e69235873adc271f8861912ec17daaa71a798c83df8cc3a9b88520708c9"
		score = 75
		quality = 63
		tags = ""

	strings:
		$s1 = "getcrypt@cock.li" nocase ascii wide
		$s2 = "cryptget@tutanota.com" nocase ascii wide
		$s3 = "cryptget@tutanota.com" nocase ascii wide
		$s4 = "offtitan@pm.me" nocase ascii wide
		$s5 = "offtitan@cock.li" nocase ascii wide
		$s6 = "un42@protonmail.com" nocase ascii wide

	condition:
		any of them
}
