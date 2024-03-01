rule MICROSOFT_Trojan_Win32_Plalsalog : Platinum
{
	meta:
		description = "Loader / possible incomplete LSA Password Filter"
		author = "Microsoft"
		id = "e5c7e07d-79e3-580f-ac24-28920a9b0e70"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L122-L140"
		license_url = "N/A"
		hash = "fa087986697e4117c394c9a58cb9f316b2d9f7d8"
		logic_hash = "58d937be220c0f356396c28367ab63ff4c4a6bf2cbf9e0ce8f8cac25e4fe3fec"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "29cb81dbe491143b2f8b67beaeae6557d8944ab4"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {8A 1C 01 32 DA 88 1C 01 8B 74 24 0C 41 3B CE 7C EF 5B 5F C6 04 01 00 5E 81 C4 04 01 00 00 C3}
		$str2 = "PasswordChangeNotify"

	condition:
		$str1 and $str2
}
