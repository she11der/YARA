rule MICROSOFT_Trojan_Win32_Plaklog : Platinum
{
	meta:
		description = "Hook-based keylogger"
		author = "Microsoft"
		id = "4faffe66-63fc-5498-be59-dbbbb909ad74"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L227-L246"
		license_url = "N/A"
		hash = "831a5a29d47ab85ee3216d4e75f18d93641a9819"
		logic_hash = "af8dd0749d07f0b99cf3dd24bc144d38fe6db00f699bc7f45f197ac6e1663cad"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "e18750207ddbd939975466a0e01bd84e75327dda"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "++[%s^^unknown^^%s]++"
		$str2 = "vtfs43/emm"
		$str3 = {33 C9 39 4C 24 08 7E 10 8B 44 24 04 03 C1 80 00 08 41 3B 4C 24 08 7C F0 C3}

	condition:
		$str1 and $str2 and $str3
}
