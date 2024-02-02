rule SIGNATURE_BASE_Php_Backdoor_Php
{
	meta:
		description = "Semi-Auto-generated  - file php-backdoor.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "aca53071-f793-538d-bbeb-34469cdb4d1f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3631-L3643"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
		logic_hash = "acab82b40760b45d49da51953f78c69166955de54918634c9bfe394208cdbb56"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "http://michaeldaw.org   2006"
		$s1 = "or http://<? echo $SERVER_NAME.$REQUEST_URI; ?>?d=c:/windows on win"
		$s3 = "coded by z0mbie"

	condition:
		1 of them
}