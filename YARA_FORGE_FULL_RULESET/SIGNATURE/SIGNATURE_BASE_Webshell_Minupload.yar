rule SIGNATURE_BASE_Webshell_Minupload
{
	meta:
		description = "Web Shell - file minupload.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1953-L1967"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ec905a1395d176c27f388d202375bdf9"
		logic_hash = "53dea3ea0e2cf83907273fa7f64b21b40e9a5c8e4aa34e5d46d2762396fa89ce"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
		$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"

	condition:
		all of them
}
