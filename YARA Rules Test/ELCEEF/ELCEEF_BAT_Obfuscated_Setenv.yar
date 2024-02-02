rule ELCEEF_BAT_Obfuscated_Setenv
{
	meta:
		description = "Detects batch script with obfuscated SET command located directly after @echo off"
		author = "marcin@ulikowski.pl"
		id = "999d192e-a792-5953-b9e2-de4b298444d3"
		date = "2023-05-01"
		modified = "2023-05-05"
		reference = "https://twitter.com/wdormann/status/1651631372438585344"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/Suspicious_BAT.yara#L1-L20"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "da3a2245207d79cb720079cc2bc88d5f9db22fc16601d21e7c8dcea381ed11e9"
		score = 75
		quality = 75
		tags = ""
		hash1 = "a0f43c5748ada07a12af81dda2460045030f936a8d5081f3a403f85c2a9668f8"
		hash2 = "1a0ca873412474a6437d33e48071aa0169f8317b5c996e1b10a41791707b2cf5"
		hash3 = "83e47d4f3dd43ed01dc573f0b83e9e71f0ec75b6ea5712f640585d01d8aedf3c"
		hash4 = "cf351a2b1f0a157a92be2e01e460140e2c1d0ee1685474144f2203a97d2de489"

	strings:
		$s1 = { 40 65 63 68 6f 20 6f 66 66 0d 0a ( 73 65 25 | 73 25 | 25 ) [2-26] 3a 7e [0-6] 3? 25 ( 25 | 20 | 65 25 | 74 20 | 65 74 20 ) }
		$s2 = { 40 65 63 68 6f 20 6f 66 66 0d 0a 73 65 74 20 22 [4] 3d 73 65 74 20 22 0d 0a 25 }

	condition:
		$s1 in (0..4) or $s2 in (0..4)
}