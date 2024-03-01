rule MICROSOFT_Trojan_Win32_Plainst2 : Platinum
{
	meta:
		description = "Zc tool"
		author = "Microsoft"
		id = "7202eeb5-269d-5e9a-9a93-bdf489639e74"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L373-L392"
		license_url = "N/A"
		hash = "3f2ce812c38ff5ac3d813394291a5867e2cddcf2"
		logic_hash = "4dc897a598fd491694f8fe3ec4ae9278dc341ffd9f95f416eb5e98fb5aa200e4"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "88ff852b1b8077ad5a19cc438afb2402462fbd1a"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "Connected [%s:%d]..."
		$str2 = "reuse possible: %c"
		$str3 = "] => %d%%\x0a"

	condition:
		$str1 and $str2 and $str3
}
