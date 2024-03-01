rule SIGNATURE_BASE_Webshell_Customize
{
	meta:
		description = "Web Shell - file customize.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1557-L1570"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "d55578eccad090f30f5d735b8ec530b1"
		logic_hash = "462d97427793ef6e897b33f4fd02d452ad8cd11ddef21aa25d13efc981eb3afb"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"

	condition:
		all of them
}
