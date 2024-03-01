rule SIGNATURE_BASE_Webshell_Webshells_New_Jspyyy
{
	meta:
		description = "Web shells - generated from file jspyyy.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3420-L3433"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
		logic_hash = "0afe45556aa7b562672cc4b609cf001aaa617b03028322abac6524f666b069e1"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"

	condition:
		all of them
}
