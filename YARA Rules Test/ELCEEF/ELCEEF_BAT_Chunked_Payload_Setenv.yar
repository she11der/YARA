rule ELCEEF_BAT_Chunked_Payload_Setenv
{
	meta:
		description = "Detects batch script storing chunks of payload in random environment variables"
		author = "marcin@ulikowski.pl"
		id = "18f3ddac-bc19-5b54-891e-93271d59490a"
		date = "2023-05-05"
		modified = "2023-06-05"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/Suspicious_BAT.yara#L22-L37"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "6b202d1a5723db664c7ca689c73fc1f84365801fd56fc9a035c8d3a0b6b2b9da"
		score = 75
		quality = 75
		tags = ""
		hash1 = "f73521adbf89be99c4d7ea74ebf7fed815af49ce4dc060656d7c9c631e4d0538"

	strings:
		$echo = "@echo off"
		$set = { ( 0d 0a | 26 20 ) 73 65 74 20 22 [10] 3d [2-6] 22 }

	condition:
		$echo in (0..4) and #set>10
}