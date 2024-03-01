rule SIGNATURE_BASE_Webshell_Jsp_Action
{
	meta:
		description = "Web Shell - file action.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1873-L1887"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"
		logic_hash = "5ea7d074d0fe98cf2514a65231013a374532d6b3aa2487bcc34d4285f558752a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
		$s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword

	condition:
		all of them
}
