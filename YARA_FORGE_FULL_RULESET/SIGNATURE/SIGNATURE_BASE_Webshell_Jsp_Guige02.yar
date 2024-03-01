rule SIGNATURE_BASE_Webshell_Jsp_Guige02
{
	meta:
		description = "Web Shell - file guige02.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1601-L1615"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a3b8b2280c56eaab777d633535baf21d"
		logic_hash = "c214e50b209970c03d389d97673901ec44b2727e5c7588e5e4d0a644cc691423"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
		$s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"

	condition:
		all of them
}
