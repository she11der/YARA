rule SIGNATURE_BASE_Webshell_Jsp_Zx
{
	meta:
		description = "Web Shell - file zx.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1175-L1188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "67627c264db1e54a4720bd6a64721674"
		logic_hash = "d97df624801d0f24141dfe7074d290a56e639af7d867c907362ff4434c3eeac0"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"

	condition:
		all of them
}
