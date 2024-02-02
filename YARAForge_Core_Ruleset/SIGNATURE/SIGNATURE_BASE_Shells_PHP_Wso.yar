rule SIGNATURE_BASE_Shells_PHP_Wso
{
	meta:
		description = "Semi-Auto-generated  - file wso.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "fdce6094-a88e-5da6-aeb0-bc97b15bf397"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4330-L4341"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "33e2891c13b78328da9062fbfcf898b6"
		logic_hash = "31ef69228b66b30300006f63b1e4d6e92c2512caca4bd915d418b48564b39c47"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$back_connect_p=\"IyEvdXNyL2Jpbi9wZXJsDQp1c2UgU29ja2V0Ow0KJGlhZGRyPWluZXRfYXRvbi"
		$s3 = "echo '<h1>Execution PHP-code</h1><div class=content><form name=pf method=pos"

	condition:
		1 of them
}