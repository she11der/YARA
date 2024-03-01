rule SIGNATURE_BASE_Webshell_Webshells_New_Jjjsp3
{
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3448-L3461"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "949ffee1e07a1269df7c69b9722d293e"
		logic_hash = "44889540effa2f71889e7f6d0c5d12486e256d83b9230c4902d56f6a59b7939b"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"

	condition:
		all of them
}
