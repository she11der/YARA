rule SIGNATURE_BASE_Simple_Backdoor_Php
{
	meta:
		description = "Semi-Auto-generated  - file simple-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "5607f501-a750-59be-9595-5ac71ea6f74b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4145-L4157"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
		logic_hash = "e2e98580b59727313de298fab0009704f621b1b6556220d5065118d960f7a068"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->"
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword

	condition:
		2 of them
}
