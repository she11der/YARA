rule SIGNATURE_BASE_Webshell_PHANTASMA
{
	meta:
		description = "PHP Webshells Github Archive - file PHANTASMA.php"
		author = "Florian Roth (Nextron Systems)"
		id = "b36a7dbb-7d40-5fca-8409-c8822298005c"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6498-L6512"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "cd12d42abf854cd34ff9e93a80d464620af6d75e"
		logic_hash = "355be62807182f9a53bac20a6dead8f0a3bee83b6bdc4566502c157f16076b9b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s12 = "\"    printf(\\\"Usage: %s [Host] <port>\\\\n\\\", argv[0]);\\n\" ." fullword
		$s15 = "if ($portscan != \"\") {" fullword
		$s16 = "echo \"<br>Banner: $get <br><br>\";" fullword
		$s20 = "$dono = get_current_user( );" fullword

	condition:
		3 of them
}