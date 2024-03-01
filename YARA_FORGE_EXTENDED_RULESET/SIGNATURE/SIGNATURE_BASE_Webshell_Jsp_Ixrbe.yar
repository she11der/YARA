rule SIGNATURE_BASE_Webshell_Jsp_Ixrbe
{
	meta:
		description = "Web Shell - file IXRbE.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1364-L1377"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e26e7e0ebc6e7662e1123452a939e2cd"
		logic_hash = "8710d092b81c5de1e328ad6e57e5c4a25748cc92844198038c103dabc1e76e77"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"

	condition:
		all of them
}
