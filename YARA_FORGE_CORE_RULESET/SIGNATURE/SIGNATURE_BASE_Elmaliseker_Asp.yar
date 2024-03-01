rule SIGNATURE_BASE_Elmaliseker_Asp
{
	meta:
		description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "7ecf3d5c-be91-579e-905b-5f2ad03a0e42"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4355-L4368"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
		logic_hash = "969f0f12449375a9ebbb8a68fd4b3db395927416d5cceccdb7f2c64310430880"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
		$s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
		$s2 = "dim zombie_array,special_array"
		$s3 = "http://vnhacker.org"

	condition:
		1 of them
}
