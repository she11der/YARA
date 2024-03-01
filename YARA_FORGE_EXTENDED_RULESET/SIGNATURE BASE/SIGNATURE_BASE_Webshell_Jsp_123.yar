rule SIGNATURE_BASE_Webshell_Jsp_123
{
	meta:
		description = "Web Shell - file 123.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L918-L933"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c691f53e849676cac68a38d692467641"
		logic_hash = "48925d3a302bf09ecb3f031301ca8afc722c7ef53b87efa27a3c4b58ee15217d"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
		$s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword

	condition:
		all of them
}
