rule SIGNATURE_BASE_Remsec_Packer_A
{
	meta:
		description = "Detects malware from Symantec's Strider APT report"
		author = "Symantec"
		id = "d75198ab-b1ea-572a-a674-9a38c3e2958b"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_strider.yara#L64-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "b46a41686fbf1c63e8a8b583859f23bf789bc9f11ee6b1fb01bb08e602772e76"
		score = 80
		quality = 85
		tags = ""

	strings:
		$code = { 69 ( C? | D? | E? | F? ) AB 00 00 00 ( 81 | 41 81 ) C? CD 2B 00 00 ( F7 | 41 F7 ) E? ( C1 | 41 C1 ) E? 0D ( 69 | 45 69 ) ( C? | D? | E? | F? ) 85 CF 00 00 ( 29 | 41 29 | 44 29 | 45 29 | 2B | 41 2B | 44 2B | 45 2B ) }

	condition:
		all of them
}
