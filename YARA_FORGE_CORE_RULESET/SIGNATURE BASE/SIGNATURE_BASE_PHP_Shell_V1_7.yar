rule SIGNATURE_BASE_PHP_Shell_V1_7
{
	meta:
		description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
		author = "Florian Roth (Nextron Systems)"
		id = "7eb69ac3-90bb-5a44-8dcd-e71f5edcf18f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8611-L8622"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "b5978501c7112584532b4ca6fb77cba5"
		logic_hash = "e03904177309de9ce1afa0b12bf70913b106650c3db5807f9d4ccb91fb2ade77"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"

	condition:
		all of them
}
