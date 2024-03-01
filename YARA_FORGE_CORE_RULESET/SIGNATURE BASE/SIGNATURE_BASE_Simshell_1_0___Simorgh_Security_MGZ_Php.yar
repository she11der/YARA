rule SIGNATURE_BASE_Simshell_1_0___Simorgh_Security_MGZ_Php
{
	meta:
		description = "Semi-Auto-generated  - file SimShell 1.0 - Simorgh Security MGZ.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "51565555-a17b-59c7-b433-c3166fe0d7f0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4251-L4264"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "37cb1db26b1b0161a4bf678a6b4565bd"
		logic_hash = "590a1572877fafcd4425a04c12cd56194f03a63b7acad93c39d4b16dc5a1902d"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Simorgh Security Magazine "
		$s1 = "Simshell.css"
		$s2 = "} elseif (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $_REQUEST['command'], "
		$s3 = "www.simorgh-ev.com"

	condition:
		2 of them
}
