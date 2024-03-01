rule MICROSOFT_Trojan_Win32_Platual : Platinum
{
	meta:
		description = "Installer component"
		author = "Microsoft"
		id = "ac963388-cc73-5842-96be-77349398efcc"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L21-L38"
		license_url = "N/A"
		hash = "e0ac2ae221328313a7eee33e9be0924c46e2beb9"
		logic_hash = "3692b5c1d873fb799b64ea69f3762177198dbb0fb971bc29bb80048c0de735d4"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "ccaf36c2d02c3c5ca24eeeb7b1eae7742a23a86a"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$class_name = "AVCObfuscation"
		$scrambled_dir = { A8 8B B8 E3 B1 D7 FE 85 51 32 3E C0 F1 B7 73 99 }

	condition:
		$class_name and $scrambled_dir
}
