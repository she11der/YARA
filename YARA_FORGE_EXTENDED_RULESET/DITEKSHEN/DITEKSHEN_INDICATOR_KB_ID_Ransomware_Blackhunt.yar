rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Blackhunt
{
	meta:
		description = "Detects files referencing identities associated with BlackHunt ransomware"
		author = "ditekShen"
		id = "87613fcc-7d9a-57ba-9653-c48760dd5ef0"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L1725-L1739"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6b875d4abdedc8032f89ab3cbdf4acdc855d83b5bcc08f96b2fbc38b4a5daa7f"
		score = 75
		quality = 61
		tags = ""

	strings:
		$s1 = "onion746@onionmail.com" ascii wide nocase
		$s2 = "amike1096@gmail.com" ascii wide nocase
		$s3 = "decryptyourdata@msgsafe.io" ascii wide nocase
		$s4 = "decryptyourdata@onionmail.org" ascii wide nocase
		$s5 = "Teikobest@gmail.com" ascii wide nocase
		$s6 = "Loxoclash@gmail.com" ascii wide nocase
		$s7 = "://sdjf982lkjsdvcjlksaf2kjhlksvvnktyoiasuc92lf.onion" ascii wide nocase

	condition:
		any of them
}
