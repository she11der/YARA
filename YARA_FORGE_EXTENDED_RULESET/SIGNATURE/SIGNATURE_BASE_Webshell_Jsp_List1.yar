rule SIGNATURE_BASE_Webshell_Jsp_List1
{
	meta:
		description = "Web Shell - file list1.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L887-L901"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"
		logic_hash = "61ecafe477d98c5eb6887a9ff50960fc28b84512d09a36c02588159b08b395a4"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
		$s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""

	condition:
		all of them
}
