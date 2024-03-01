rule MICROSOFT_Trojan_Win32_Dipsind_B : Platinum
{
	meta:
		description = "Dipsind Family"
		author = "Microsoft"
		id = "513c18a6-af25-58ad-9232-9a089f4ced3d"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L59-L77"
		license_url = "N/A"
		logic_hash = "1f99f298dc4d1483eb95cfb898dd9eee32b2f72a8da562f58a57f44559cbd2c7"
		score = 75
		quality = 80
		tags = ""
		sample_sha1 = "09e0dfbb5543c708c0dd6a89fd22bbb96dc4ca1c"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$frg1 = {8D 90 04 01 00 00 33 C0 F2 AE F7 D1 2B F9 8B C1 8B F7 8B FA C1 E9 02 F3 A5 8B C8 83 E1 03 F3 A4 8B 4D EC 8B 15 ?? ?? ?? ?? 89 91 ?? 07 00 00 }
		$frg2 = {68 A1 86 01 00 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA}
		$frg3 = {C0 E8 07 D0 E1 0A C1 8A C8 32 D0 C0 E9 07 D0 E0 0A C8 32 CA 80 F1 63}

	condition:
		$frg1 and $frg2 and $frg3
}
