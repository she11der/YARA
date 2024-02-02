rule SIGNATURE_BASE_Backup_Php_Often_With_C99Shell
{
	meta:
		description = "Semi-Auto-generated  - file backup.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4199-L4211"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "aeee3bae226ad57baf4be8745c3f6094"
		logic_hash = "e27d00ebfbac2565568b9a97552a331db91b4e9aa318febb048937f5c3a1a1ba"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "#phpMyAdmin MySQL-Dump" fullword
		$s2 = ";db_connect();header('Content-Type: application/octetstr"
		$s4 = "$data .= \"#Database: $database" fullword

	condition:
		all of them
}