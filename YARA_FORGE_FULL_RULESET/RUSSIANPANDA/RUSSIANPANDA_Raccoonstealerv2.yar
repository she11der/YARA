rule RUSSIANPANDA_Raccoonstealerv2 : FILE
{
	meta:
		description = "Detects the latest unpacked/unobfuscated build 2.1.0-4"
		author = "RussianPanda"
		id = "eda6216a-219b-5f60-8084-4c0c240a4cb4"
		date = "2023-04-17"
		modified = "2023-05-05"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/RaccoonStealer_v2/raccoonstealerv2_2.1.0-4_build.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "e2226f08753a3571045953363c04ec52de3c79cd0cd29e7ecb6afaf2ad573e4e"
		score = 50
		quality = 85
		tags = "FILE"

	strings:
		$pattern1 = {B9 ?? ?? ?? 00 E8 ?? ?? ?? 00 ?? ?? 89 45 E8}
		$pattern2 = {68 ?? ?? ?? 00 ?? 68 01 00 1F 00}
		$pattern3 = {68 ?? ?? ?? 00 ?? ?? 68 01 00 1F 00 FF 15 64 ?? ?? 00}
		$m1 = {68 ?? ?? ?? 00 ?? 00 68 01 00 1f 00 ff 15 64 ?? ?? 00}
		$m2 = {68 ?? ?? ?? 00 ?? 68 01 00 1f 00 ff 15 64 ?? ?? 00}

	condition:
		2 of ($pattern*) and uint16(0)==0x5A4D and 1 of ($m*) and uint32( uint32(0x3C))==0x00004550 and filesize <200KB
}
