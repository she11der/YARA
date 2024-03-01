rule MICROSOFT_Trojan_Win32_Plakpers : Platinum
{
	meta:
		description = "Injector / loader component"
		author = "Microsoft"
		id = "d37c6ac5-ca46-5fb2-80bd-ab63c8dbcd21"
		date = "2016-04-12"
		modified = "2016-12-21"
		reference = "https://www.threatminer.org/report.php?q=Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf&y=2016"
		source_url = "https://github.com/mikesxrs/Open-Source-YARA-rules/blob/ec0056f767db98bf6d5fd63877ad51fb54d350e9/Microsoft/Platinum.yara#L352-L371"
		license_url = "N/A"
		hash = "fa083d744d278c6f4865f095cfd2feabee558056"
		logic_hash = "d3705a34232ba2b00786b32f84823d3a6b037ed6a5882983e69addc020bc0b35"
		score = 75
		quality = 80
		tags = ""
		unpacked_sample_sha1 = "3a678b5c9c46b5b87bfcb18306ed50fadfc6372e"
		activity_group = "Platinum"
		version = "1.0"

	strings:
		$str1 = "MyFileMappingObject"
		$str2 = "[%.3u]  %s  %s  %s [%s:" wide
		$str3 = "%s\\{%s}\\%s" wide

	condition:
		$str1 and $str2 and $str3
}
