rule SIGNATURE_BASE_Webshell_Mysql_Tool
{
	meta:
		description = "PHP Webshells Github Archive - file mysql_tool.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a22a0a5c-a686-517e-b1f9-279edab0616b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6544-L6556"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "c9cf8cafcd4e65d1b57fdee5eef98f0f2de74474"
		logic_hash = "611636b3fa9a3163574b18cf8eacebea9733a1ad381261387f79a532b003e8fd"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s12 = "$dump .= \"-- Dumping data for table '$table'\\n\";" fullword
		$s20 = "$dump .= \"CREATE TABLE $table (\\n\";" fullword

	condition:
		2 of them
}