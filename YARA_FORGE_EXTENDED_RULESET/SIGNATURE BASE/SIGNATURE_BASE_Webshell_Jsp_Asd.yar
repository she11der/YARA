rule SIGNATURE_BASE_Webshell_Jsp_Asd
{
	meta:
		description = "Web Shell - file asd.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L2011-L2025"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a042c2ca64176410236fcc97484ec599"
		logic_hash = "6620b796b55a67010cd3edebc2ec84c2657717722129ea46288d262cfd1c7e1c"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
		$s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"

	condition:
		all of them
}
