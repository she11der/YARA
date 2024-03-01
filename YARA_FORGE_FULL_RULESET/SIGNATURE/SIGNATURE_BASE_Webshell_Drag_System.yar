rule SIGNATURE_BASE_Webshell_Drag_System
{
	meta:
		description = "Web Shell - file system.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L521-L534"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "15ae237cf395fb24cf12bff141fb3f7c"
		logic_hash = "8ea8d9d64521f47f1396e4f4d6c8f4a71fa1a643799ec408e1d2e0f255dc4996"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"

	condition:
		all of them
}
