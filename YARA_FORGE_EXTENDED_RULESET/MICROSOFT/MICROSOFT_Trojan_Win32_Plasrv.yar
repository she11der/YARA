rule MICROSOFT_Trojan_Win32_Plasrv : Platinum
{
	meta:
		description = "Hotpatching Injector"
		author = "Microsoft"
		id = "2a099b68-fb13-5926-8a86-4d788326609c"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L1-L19"
		license_url = "N/A"
		hash = "ff7f949da665ba8ce9fb01da357b51415634eaad"
		logic_hash = "5978502454d66a930a535ffe61d78f2106c3c17c8df9be1b22bc10ef900c891f"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "dff2fee984ba9f5a8f5d97582c83fca4fa1fe131"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$Section_name = ".hotp1"
		$offset_x59 = { C7 80 64 01 00 00 00 00 01 00 }

	condition:
		$Section_name and $offset_x59
}
