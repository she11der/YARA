rule SIGNATURE_BASE_Dive_Shell_1_0___Emperor_Hacking_Team_Php
{
	meta:
		description = "Semi-Auto-generated  - file Dive Shell 1.0 - Emperor Hacking Team.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "d75294a4-a0a7-5c74-bb7a-766db477633c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4171-L4184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "1b5102bdc41a7bc439eea8f0010310a5"
		logic_hash = "bd51b625359799178ad3c8e02ba5bb5fca89e6e14769b86dd35c2b8a1049599f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Emperor Hacking TEAM"
		$s1 = "Simshell" fullword
		$s2 = "ereg('^[[:blank:]]*cd[[:blank:]]"
		$s3 = "<form name=\"shell\" action=\"<?php echo $_SERVER['PHP_SELF'] ?>\" method=\"POST"

	condition:
		2 of them
}