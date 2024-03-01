rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Zeppelin
{
	meta:
		description = "Detects files referencing identities associated with Zeppelin ransomware"
		author = "ditekShen"
		id = "f3bbfcd0-c66c-589e-ae04-904314d6a869"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L449-L462"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "66dd92423cfac32de4bea95ad0c9594cb449dc897cc6315d782c1db6de7dc5b1"
		score = 75
		quality = 63
		tags = ""

	strings:
		$s1 = "kd8eby0@inboxhub.net" ascii wide nocase
		$s2 = "kd8eby0@onionmail.org" ascii wide nocase
		$s3 = "kd8eby0@nuke.africa" ascii wide nocase
		$s4 = "uspex1@cock.li" ascii wide nocase
		$s5 = "uspex2@cock.li" ascii wide nocase
		$s6 = "China.Helper@aol.com" ascii wide nocase

	condition:
		any of them
}
