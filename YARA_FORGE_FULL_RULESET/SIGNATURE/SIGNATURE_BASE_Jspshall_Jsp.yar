rule SIGNATURE_BASE_Jspshall_Jsp
{
	meta:
		description = "Semi-Auto-generated  - file jspshall.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "4bccad33-d26e-52c2-b7f8-802f2c8f3889"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4265-L4277"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "efe0f6edaa512c4e1fdca4eeda77b7ee"
		logic_hash = "94c458d3f38ba21348b0202e2b81bbbc3859e97d64f101a9ea7ec6f036e38bc5"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "kj021320"
		$s1 = "case 'T':systemTools(out);break;"
		$s2 = "out.println(\"<tr><td>\"+ico(50)+f[i].getName()+\"</td><td> file"

	condition:
		2 of them
}
