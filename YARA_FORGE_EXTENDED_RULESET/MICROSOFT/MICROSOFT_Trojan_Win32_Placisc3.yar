rule MICROSOFT_Trojan_Win32_Placisc3 : Platinum
{
	meta:
		description = "Dipsind variant"
		author = "Microsoft"
		id = "f2089236-8227-5042-9086-fb77aebd147f"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L311-L329"
		license_url = "N/A"
		hash = "1b542dd0dacfcd4200879221709f5fa9683cdcda"
		logic_hash = "3a1afe737c08b4d9149380e04f5d6240a00b237822c3c82d82eccf5412cb05d1"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "bbd4992ee3f3a3267732151636359cf94fb4575d"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = {BA 6E 00 00 00 66 89 95 ?? ?? FF FF B8 73 00 00 00 66 89 85 ?? ?? FF FF B9 64 00 00 00 66 89 8D ?? ?? FF FF BA 65 00 00 00 66 89 95 ?? ?? FF FF B8 6C 00 00 00}
		$str2 = "VPLRXZHTU"
		$str3 = {8B 44 24 ?? 8A 04 01 41 32 C2 3B CF 7C F2 88 03}

	condition:
		$str1 and $str2 and $str3
}
