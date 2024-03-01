rule ELCEEF_BAT_Begin_Substring_Env
{
	meta:
		description = "Detects suspicious substring syntax at the begining of batch script"
		author = "marcin@ulikowski.pl"
		id = "3fca187b-d2e7-595c-9330-25141a54285b"
		date = "2023-06-02"
		modified = "2023-06-05"
		reference = "https://cybersecurity.att.com/blogs/labs-research/seroxen-rat-for-sale"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/Suspicious_BAT.yara#L39-L55"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "cc5e6e511bbc0a5cbb277ed0cbac1f2b21db8e21c4cdc802b6a1c3313d3b55cc"
		score = 65
		quality = 75
		tags = ""
		hash1 = "8ace121fae472cc7ce896c91a3f1743d5ccc8a389bc3152578c4782171c69e87"

	strings:
		$echo = "@echo off"
		$substr = { 3a 7e ( 3? 2c 3? | 2d 3? 2c 3? | 3? 2c 2d 3? | 3? 3? 2c 3? | 2d 3? 3? 2c 3? | 3? 3? 2c 2d 3? ) 25 }

	condition:
		$echo in (0..4) and $substr in (10..100)
}
