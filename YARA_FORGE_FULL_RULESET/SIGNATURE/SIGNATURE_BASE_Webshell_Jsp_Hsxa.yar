rule SIGNATURE_BASE_Webshell_Jsp_Hsxa
{
	meta:
		description = "Web Shell - file hsxa.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L565-L578"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"
		logic_hash = "7f79b66d87f638bc09ee576de4dc4a8c5b1da7c406d318eeff7a4221c35d2313"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"

	condition:
		all of them
}
