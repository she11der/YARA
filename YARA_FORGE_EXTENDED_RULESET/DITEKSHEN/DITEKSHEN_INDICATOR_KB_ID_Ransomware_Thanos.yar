rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Thanos
{
	meta:
		description = "Detects files referencing identities associated with Thanos ransomware"
		author = "ditekShen"
		id = "22ffb4c9-f113-5d3e-a466-6c384c0c6e8a"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L173-L182"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "039ea384136a1aaa261702ed75ab9358aaa1ec2d5a8d35fe4789647f39490c7c"
		score = 75
		quality = 71
		tags = ""

	strings:
		$s1 = "my-contact-email@protonmail.com" ascii wide nocase
		$s2 = "get-my-data@protonmail.com" ascii wide nocase

	condition:
		any of them
}
