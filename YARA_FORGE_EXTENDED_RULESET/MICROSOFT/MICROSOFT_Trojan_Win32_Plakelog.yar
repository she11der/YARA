rule MICROSOFT_Trojan_Win32_Plakelog : Platinum
{
	meta:
		description = "Raw-input based keylogger"
		author = "Microsoft"
		id = "26f552e6-9abf-59ca-a8df-19473d6d775a"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L164-L184"
		license_url = "N/A"
		hash = "3907a9e41df805f912f821a47031164b6636bd04"
		logic_hash = "e18cae8bb2a79f7d39a80669896b1f7a7c1726f14192abcc91388fd53781ffef"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "960feeb15a0939ec0b53dcb6815adbf7ac1e7bb2"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "<0x02>" wide
		$str2 = "[CTR-BRK]" wide
		$str3 = "[/WIN]" wide
		$str4 = {8A 16 8A 18 32 DA 46 88 18 8B 15 08 E6 42 00 40 41 3B CA 72 EB 5E 5B}

	condition:
		$str1 and $str2 and $str3 and $str4
}
