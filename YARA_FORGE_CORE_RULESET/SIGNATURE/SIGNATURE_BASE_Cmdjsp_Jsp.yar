rule SIGNATURE_BASE_Cmdjsp_Jsp
{
	meta:
		description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "048478a8-9622-54c7-80ed-e4e223d14500"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4875-L4888"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b815611cc39f17f05a73444d699341d4"
		logic_hash = "8b0e425c7d71ea2c536192ff186665e7f0fbdbc0e0d195d7107ac57cf9bd1773"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
		$s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s2 = "cmdjsp.jsp"
		$s3 = "michaeldaw.org" fullword

	condition:
		2 of them
}
