rule MICROSOFT_Trojan_Win32_Plainst : Platinum
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "41a4770a-b4d8-5ddc-8b4f-a4e87a1f3923"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L186-L204"
		license_url = "N/A"
		hash = "99c08d31af211a0e17f92dd312ec7ca2b9469ecb"
		logic_hash = "5fa8e52c044e05d96c2c09b69ef884ed0ea863ceb3ba00cdf243a4907050de69"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "dcb6cf7cf7c8fdfc89656a042f81136bda354ba6"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {66 8B 14 4D 18 50 01 10 8B 45 08 66 33 14 70 46 66 89 54 77 FE 66 83 7C 77 FE 00 75 B7 8B 4D FC 89 41 08 8D 04 36 89 41 0C 89 79 04}
		$str2 = {4b D391 49 A1 80 91 42 83 B6 33 28 36 6B 90 97}

	condition:
		$str1 and $str2
}
