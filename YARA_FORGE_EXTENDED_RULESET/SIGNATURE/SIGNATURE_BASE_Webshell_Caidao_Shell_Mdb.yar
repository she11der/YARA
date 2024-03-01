rule SIGNATURE_BASE_Webshell_Caidao_Shell_Mdb
{
	meta:
		description = "Web Shell - file mdb.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L463-L476"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "fbf3847acef4844f3a0d04230f6b9ff9"
		logic_hash = "89f7692acd754992f9379b9b4661a01d6ab95cb85a3c2699928aa5ed3a3ac8c5"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<% execute request(\"ice\")%>a " fullword

	condition:
		all of them
}
