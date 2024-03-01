rule SIGNATURE_BASE_Jsp_Reverse_Jsp
{
	meta:
		description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "4953b230-4cd9-55d6-a3cb-8d3713e7fb0c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3752-L3764"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "8b0e6779f25a17f0ffb3df14122ba594"
		logic_hash = "bdd2db4c032b25faaaf3a3a8e769000013f643ecfcb8b0374165a244ad2162a6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "// backdoor.jsp"
		$s1 = "JSP Backdoor Reverse Shell"
		$s2 = "http://michaeldaw.org"

	condition:
		2 of them
}
