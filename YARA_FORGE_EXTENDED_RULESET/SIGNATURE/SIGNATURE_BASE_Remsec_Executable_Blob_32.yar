rule SIGNATURE_BASE_Remsec_Executable_Blob_32
{
	meta:
		description = "Detects malware from Symantec's Strider APT report"
		author = "Symantec"
		id = "d7a7e57a-b117-5da8-a7a2-4c6351bd9072"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_strider.yara#L8-L20"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1cfc43ab15b3d220a636c150315c30f5654e53fad67d20534ce4d5c00295e35e"
		score = 80
		quality = 85
		tags = ""

	strings:
		$code = { 31 06 83 C6 04 D1 E8 73 05 35 01 00 00 D0 E2 F0 }

	condition:
		all of them
}
