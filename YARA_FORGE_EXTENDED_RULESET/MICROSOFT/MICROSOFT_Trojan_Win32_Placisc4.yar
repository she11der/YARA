rule MICROSOFT_Trojan_Win32_Placisc4 : Platinum
{
	meta:
		description = "Installer for Dipsind variant"
		author = "Microsoft"
		id = "04770059-06ca-5315-a7b3-0e9fbcecfc57"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L331-L350"
		license_url = "N/A"
		hash = "3d17828632e8ff1560f6094703ece5433bc69586"
		logic_hash = "4fa4f48d6747cde6d635eca2f5277da7be17473a561828eafa604fbc2801073a"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "2abb8e1e9cac24be474e4955c63108ff86d1a034"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {8D 71 01 8B C6 99 BB 0A00 00 00 F7 FB 0F BE D2 0F BE 04 39 2B C2 88 04 39 84 C0 74 0A}
		$str2 = {6A 04 68 00 20 00 00 68 00 00 40 00 6A 00 FF D5}
		$str3 = {C6 44 24 ?? 64 C6 44 24 ?? 6F C6 44 24 ?? 67 C6 44 24 ?? 32 C6 44 24 ?? 6A}

	condition:
		$str1 and $str2 and $str3
}
