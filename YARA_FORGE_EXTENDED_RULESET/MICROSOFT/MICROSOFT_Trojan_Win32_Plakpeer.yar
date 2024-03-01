rule MICROSOFT_Trojan_Win32_Plakpeer : Platinum
{
	meta:
		description = "Zc tool v2"
		author = "Microsoft"
		id = "e573279b-4a7b-5e15-8ab2-a77cd98a8b6e"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L394-L414"
		license_url = "N/A"
		hash = "2155c20483528377b5e3fde004bb604198463d29"
		logic_hash = "cc34ce9f12c95133872783090efd5813d3e2f44a1c726d29b2ba834509c9a1d5"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "dc991ef598825daabd9e70bac92c79154363bab2"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "@@E0020(%d)" wide
		$str2 = /exit.{0,3}@exit.{0,3}new.{0,3}query.{0,3}rcz.{0,3}scz/ wide
		$str3 = "---###---" wide
		$str4 = "---@@@---" wide

	condition:
		$str1 and $str2 and $str3 and $str4
}
