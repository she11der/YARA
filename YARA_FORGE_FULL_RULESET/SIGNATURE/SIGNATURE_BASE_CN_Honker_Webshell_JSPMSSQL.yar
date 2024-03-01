rule SIGNATURE_BASE_CN_Honker_Webshell_JSPMSSQL : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "061c1e53-edd0-5838-8d0f-6fb8f4fa078a"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L354-L369"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c6b4faecd743d151fe0a4634e37c9a5f6533655f"
		logic_hash = "c08e69345cb09e41840a81dcd8a015f9e1be93d570b64c310be74631e5314e2f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii
		$s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii

	condition:
		filesize <35KB and all of them
}
