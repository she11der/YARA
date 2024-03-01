rule SIGNATURE_BASE_SUSP_CMD_Var_Expansion : FILE
{
	meta:
		description = "Detects Office droppers that include a variable expansion string"
		author = "Florian Roth (Nextron Systems)"
		id = "3f3ebea0-1d33-513d-b32b-9d87607525e8"
		date = "2018-09-26"
		modified = "2023-12-05"
		reference = "https://twitter.com/asfakian/status/1044859525675843585"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_susp_cmd_var_expansion.yar#L2-L14"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "68ce14cac07494645f3b5f1d61012e4fe21cfa9fa7ad4019add2368b568fe043"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$a1 = " /V:ON" ascii wide fullword

	condition:
		uint16(0)==0xcfd0 and filesize <500KB and $a1
}
