rule MICROSOFT_Trojan_Win32_Adupib : Platinum
{
	meta:
		description = "Adupib SSL Backdoor"
		author = "Microsoft"
		id = "4c5a63e5-7110-57e9-b939-df8999f317d3"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L99-L120"
		license_url = "N/A"
		hash = "d3ad0933e1b114b14c2b3a2c59d7f8a95ea0bcbd"
		logic_hash = "b83f642929a372a21e63055cd4adcab5d24b98b5a98b6fd0b35ee31e9f7f3b90"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "a80051d5ae124fd9e5cc03e699dd91c2b373978b"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "POLL_RATE"
		$str2 = "OP_TIME(end hour)"
		$str3 = "%d:TCP:*:Enabled"
		$str4 = "%s[PwFF_cfg%d]"
		$str5 = "Fake_GetDlgItemTextW: ***value***"

	condition:
		$str1 and $str2 and $str3 and $str4 and $str5
}
