rule SIGNATURE_BASE_CN_Honker_Webshell_ASP_Asp404 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp404.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "4125bb40-3f5c-53f5-b906-54fa77b119f5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_webshells.yar#L423-L439"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "bed51971288aeabba6dabbfb80d2843ec0c4ebf6"
		logic_hash = "c84be2e561a08317be11cdb0fe103f8ad182a64d8cd1bf987163ebbeabe20f00"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii
		$s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii
		$s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii

	condition:
		filesize <113KB and all of them
}
