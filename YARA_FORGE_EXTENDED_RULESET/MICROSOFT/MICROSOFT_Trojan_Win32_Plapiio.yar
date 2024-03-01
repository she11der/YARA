rule MICROSOFT_Trojan_Win32_Plapiio : Platinum
{
	meta:
		description = "JPin backdoor"
		author = "Microsoft"
		id = "538086b5-eb06-5e41-90d4-ab8f2b001c42"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L248-L267"
		license_url = "N/A"
		hash = "3119de80088c52bd8097394092847cd984606c88"
		logic_hash = "580fb1377d98e7ffcb9823b5c485ff536813e3df5d8bded745373b2a3a82fcfd"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "3acb8fe2a5eb3478b4553907a571b6614eb5455c"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "ServiceMain"
		$str2 = "Startup"
		$str3 = {C6 45 ?? 68 C6 45 ?? 4D C6 45 ?? 53 C6 45 ?? 56 C6 45 ?? 6D C6 45 ?? 6D}

	condition:
		$str1 and $str2 and $str3
}
