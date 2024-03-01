rule MICROSOFT_Trojan_Win32_Plabit : Platinum
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "cee48cbb-f980-50cc-b28a-2e80e7f1798b"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L269-L287"
		license_url = "N/A"
		logic_hash = "35f12d45c8ee5f8e2b0bcd57ae14c0ba52670abc1212f94aa276efbbe1043146"
		score = 75
		quality = 80
		tags = ""
		sample_sha1 = "6d1169775a552230302131f9385135d385efd166"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {4b D3 91 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}
		$str2 = "GetInstanceW"
		$str3 = {8B D0 83 E2 1F 8A 14 0A 30 14 30 40 3B 44 24 04 72 EE}

	condition:
		$str1 and $str2 and $str3
}
