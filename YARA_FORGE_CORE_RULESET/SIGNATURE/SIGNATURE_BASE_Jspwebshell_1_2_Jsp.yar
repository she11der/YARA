rule SIGNATURE_BASE_Jspwebshell_1_2_Jsp
{
	meta:
		description = "Semi-Auto-generated  - file JspWebshell 1.2.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "edfe6a3d-7d56-52ad-a376-cec5722e87b7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4600-L4613"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "70a0ee2624e5bbe5525ccadc467519f6"
		logic_hash = "32b3ddb00f89a3540118fe8ce5fc070556b00030dcf2b21245d38ae66e6cbc14"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "JspWebshell"
		$s1 = "CreateAndDeleteFolder is error:"
		$s2 = "<td width=\"70%\" height=\"22\">&nbsp;<%=env.queryHashtable(\"java.c"
		$s3 = "String _password =\"111\";"

	condition:
		2 of them
}
