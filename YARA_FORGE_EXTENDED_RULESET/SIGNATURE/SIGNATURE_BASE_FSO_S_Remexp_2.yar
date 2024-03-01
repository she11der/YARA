rule SIGNATURE_BASE_FSO_S_Remexp_2
{
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "501544d5-fe52-5933-8782-516ffe18f3ff"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8087-L8099"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b69670ecdbb40012c73686cd22696eeb"
		logic_hash = "e31e25a7c2b2e970a379a61d2dac335bd37cac48328eee9f3966ff5c77ef6f18"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = " Then Response.Write \""
		$s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"

	condition:
		all of them
}
