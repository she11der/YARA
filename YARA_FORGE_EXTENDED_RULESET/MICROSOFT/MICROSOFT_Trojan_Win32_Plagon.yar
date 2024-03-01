rule MICROSOFT_Trojan_Win32_Plagon : Platinum
{
	meta:
		description = "Dipsind variant"
		author = "Microsoft"
		id = "ae3b7eb0-d54e-5817-9484-c054cd27c1fd"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L142-L162"
		license_url = "N/A"
		hash = "48b89f61d58b57dba6a0ca857bce97bab636af65"
		logic_hash = "99e0d300f030bb6407de1fda488b47c73f8278e9c015bf779259ddf1b68903a2"
		score = 75
		quality = 78
		tags = ""
		unpacked_sample_sha1 = "6dccf88d89ad7b8611b1bc2e9fb8baea41bdb65a"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "VPLRXZHTU"
		$str2 = {64 6F 67 32 6A 7E 6C}
		$str3 = "Dqpqftk(Wou\"Isztk)"
		$str4 = "StartThreadAtWinLogon"

	condition:
		$str1 and $str2 and $str3 and $str4
}
