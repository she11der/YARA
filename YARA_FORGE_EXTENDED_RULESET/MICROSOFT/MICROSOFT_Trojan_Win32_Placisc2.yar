rule MICROSOFT_Trojan_Win32_Placisc2 : Platinum
{
	meta:
		description = "Dipsind variant"
		author = "Microsoft"
		id = "a5557cfa-354c-5913-9b63-f53ffb294796"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L289-L309"
		license_url = "N/A"
		hash = "bf944eb70a382bd77ee5b47548ea9a4969de0527"
		logic_hash = "6629ca96c73e48bc14c811df781973f8040f88bcbf9eda601e9f5db86e11c20b"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "d807648ddecc4572c7b04405f496d25700e0be6e"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {76 16 8B D0 83 E2 07 8A 4C 14 24 8A 14 18 32 D1 88 14 18 40 3B C7 72 EA }
		$str2 = "VPLRXZHTU"
		$str3 = "%d) Command:%s"
		$str4 = {0D 0A 2D 2D 2D 2D 2D 09 2D 2D 2D 2D 2D 2D 0D 0A}

	condition:
		$str1 and $str2 and $str3 and $str4
}
