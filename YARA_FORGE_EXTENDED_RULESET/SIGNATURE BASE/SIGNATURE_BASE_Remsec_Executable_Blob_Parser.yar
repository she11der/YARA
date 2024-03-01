rule SIGNATURE_BASE_Remsec_Executable_Blob_Parser
{
	meta:
		description = "Detects malware from Symantec's Strider APT report"
		author = "Symantec"
		id = "b2189bfe-7b84-5fe9-8829-64f49d1e2030"
		date = "2016-08-08"
		modified = "2023-12-05"
		reference = "http://www.symantec.com/connect/blogs/strider-cyberespionage-group-turns-eye-sauron-targets"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_strider.yara#L36-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2f6db962807c07ff1bbe8b53eeb386d7b0ac88f95b76439c0d8b65d597739bdd"
		score = 80
		quality = 85
		tags = ""

	strings:
		$code = { ( 0F 82 ?? ?? 00 00 | 72 ?? ) ( 80 | 41 80 ) ( 7? | 7C 24 ) 04 02 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 81 | 41 81 ) ( 3? | 3C 24 | 7D 00 ) 02 AA 02 C1 ( 0F 85 ?? ?? 00 00 | 75 ?? ) ( 8B | 41 8B | 44 8B | 45 8B ) ( 4? | 5? | 6? | 7? | ?4 24 | ?C 24 ) 06 }

	condition:
		all of them
}
