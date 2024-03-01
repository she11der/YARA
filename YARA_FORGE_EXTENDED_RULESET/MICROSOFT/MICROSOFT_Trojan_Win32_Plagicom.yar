rule MICROSOFT_Trojan_Win32_Plagicom : Platinum
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "86ef6fbf-cd39-533f-893c-72f22d73c99a"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L206-L225"
		license_url = "N/A"
		hash = "99dcb148b053f4cef6df5fa1ec5d33971a58bd1e"
		logic_hash = "d2645ecc3b4400af7d9949eeca01b1ed5d74516010658c66934772e04040d9cf"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "c1c950bc6a2ad67488e675da4dfc8916831239a7"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {C6 44 24 ?? 68 C6 44 24 ?? 4D C6 44 24 ?? 53 C6 44 24 ?? 56 C6 44 24 ?? 00}
		$str2 = "OUEMM/EMM"
		$str3 = {85 C9 7E 08 FE 0C 10 40 3B C1 7C F8 C3}

	condition:
		$str1 and $str2 and $str3
}
