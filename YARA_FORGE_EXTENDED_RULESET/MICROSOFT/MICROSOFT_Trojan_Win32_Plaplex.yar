rule MICROSOFT_Trojan_Win32_Plaplex : Platinum
{
	meta:
		description = "Variant of the JPin backdoor"
		author = "Microsoft"
		id = "2d670c09-dc0a-556e-8d00-5f94e5907d99"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L40-L57"
		license_url = "N/A"
		hash = "ca3bda30a3cdc15afb78e54fa1bbb9300d268d66"
		logic_hash = "ff7b9a52befae5f22f7c6093af44bef4a4cf271548c1caf22f30d3c8aec42de4"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "2fe3c80e98bbb0cf5a0c4da286cd48ec78130a24"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$class_name1 = "AVCObfuscation"
		$class_name2 = "AVCSetiriControl"

	condition:
		$class_name1 and $class_name2
}
