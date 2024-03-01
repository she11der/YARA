rule SIGNATURE_BASE_Webshell_B374K_Mini_Shell_Php_Php
{
	meta:
		description = "PHP Webshells Github Archive - file b374k-mini-shell-php.php.php"
		author = "Florian Roth (Nextron Systems)"
		id = "d5b0dfa5-46b5-5323-a8e8-b119d8c2c8e5"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5677-L5690"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "afb88635fbdd9ebe86b650cc220d3012a8c35143"
		logic_hash = "553bd775d9662f9410d9ab946ccffe4b2ee92e367bcc6345fa595527653280cf"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "@error_reporting(0);" fullword
		$s2 = "@eval(gzinflate(base64_decode($code)));" fullword
		$s3 = "@set_time_limit(0); " fullword

	condition:
		all of them
}
