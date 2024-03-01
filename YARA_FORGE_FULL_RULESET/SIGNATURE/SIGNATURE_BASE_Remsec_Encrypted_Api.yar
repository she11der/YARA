rule SIGNATURE_BASE_Remsec_Encrypted_Api
{
	meta:
		description = "Detects malware from Symantec's Strider APT report"
		author = "Symantec"
		id = "1aa3380b-d704-5eb9-b25d-f4bf20ae7179"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_strider.yara#L50-L62"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4f10c24a8480c17c2939fe3fecba2820b22f8a47bc2b2e73ac1080a355025d7c"
		score = 80
		quality = 85
		tags = ""

	strings:
		$open_process = { 91 9A 8F B0 9C 90 8D AF 8C 8C 9A FF }

	condition:
		all of them
}
