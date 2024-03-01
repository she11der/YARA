rule SIGNATURE_BASE_Webshell_807_Dm_Jspspyjdk5_M_Cofigrue
{
	meta:
		description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L2568-L2587"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0fc7ac740e147bd3703dac74743b19148aa7bb359cc5f347acf3b0dbe26bf752"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "14e9688c86b454ed48171a9d4f48ace8"
		hash2 = "341298482cf90febebb8616426080d1d"
		hash3 = "88fc87e7c58249a398efd5ceae636073"
		hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"

	strings:
		$s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
		$s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword

	condition:
		1 of them
}
