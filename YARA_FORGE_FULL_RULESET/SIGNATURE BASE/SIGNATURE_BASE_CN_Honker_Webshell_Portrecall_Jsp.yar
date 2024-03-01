rule SIGNATURE_BASE_CN_Honker_Webshell_Portrecall_Jsp : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "cd34cb47-c5e0-5094-a501-6a8a00d94018"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L809-L823"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "65e8e4d13ad257c820cad12eef853c6d0134fce8"
		logic_hash = "98f279c3e50308f67f88ecf8459943187ea152664fe0206c4a7d3435242df2a6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "lcx.jsp?localIP=202.91.246.59&localPort=88&remoteIP=218.232.111.187&remotePort=2" ascii

	condition:
		filesize <1KB and all of them
}
