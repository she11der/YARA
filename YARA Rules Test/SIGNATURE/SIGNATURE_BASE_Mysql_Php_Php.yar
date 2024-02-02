rule SIGNATURE_BASE_Mysql_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file mysql.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "41730336-0dce-5ed9-95b0-c911a4e3cb48"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4472-L4484"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "12bbdf6ef403720442a47a3cc730d034"
		logic_hash = "60e235310f378698ffcc3ae6a07ab5dd94a660ca4b1504cc878d9741f751d5d1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "action=mysqlread&mass=loadmass\">load all defaults"
		$s2 = "if (@passthru($cmd)) { echo \" -->\"; $this->output_state(1, \"passthru"
		$s3 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = "

	condition:
		1 of them
}