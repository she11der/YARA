rule SIGNATURE_BASE_Webshell_Jsp_Web
{
	meta:
		description = "Web Shell - file web.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L770-L783"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
		logic_hash = "ed0ace0ba5f8a9e763353c42e3e3a39da10596e8517aad33e5c5080b44e4d61a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."

	condition:
		all of them
}
