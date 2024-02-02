rule SIGNATURE_BASE_PHP_Shell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file PHP Shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "6978126c-5414-52d2-b085-6e5589716d93"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4536-L4547"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
		logic_hash = "2d5b6e08bfe9e1551dab12b01189dadc924c097427c996684bab96c48d528395"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s1 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="

	condition:
		all of them
}