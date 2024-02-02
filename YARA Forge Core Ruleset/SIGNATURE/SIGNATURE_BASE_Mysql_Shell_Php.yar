rule SIGNATURE_BASE_Mysql_Shell_Php
{
	meta:
		description = "Semi-Auto-generated  - file mysql_shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "e517984b-575c-5ead-a438-9767d2c74099"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4158-L4170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d42aec2891214cace99b3eb9f3e21a63"
		logic_hash = "dbd825e1056c41efaf80c0495ba7b6cf1c88403b997ea7ac1378512a19f7ed8a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "SooMin Kim"
		$s1 = "smkim@popeye.snu.ac.kr"
		$s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen"

	condition:
		1 of them
}