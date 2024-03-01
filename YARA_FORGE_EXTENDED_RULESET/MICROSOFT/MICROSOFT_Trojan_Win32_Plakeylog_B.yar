rule MICROSOFT_Trojan_Win32_Plakeylog_B : Platinum
{
	meta:
		description = "Keylogger component"
		author = "Microsoft"
		id = "bc84ef20-f428-5f3d-bc88-ab14991a2350"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L79-L97"
		license_url = "N/A"
		hash = "0096a3e0c97b85ca75164f48230ae530c94a2b77"
		logic_hash = "288fb5a724baaa032ca36124cf803698e315aaf61662f999f3b894049ece63f2"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "6a1412daaa9bdc553689537df0a004d44f8a45fd"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$hook = {C6 06 FF 46 C6 06 25}
		$dasm_engine = {80 C9 10 88 0E 8A CA 80 E1 07 43 88 56 03 80 F9 05}

	condition:
		$hook and $dasm_engine
}
