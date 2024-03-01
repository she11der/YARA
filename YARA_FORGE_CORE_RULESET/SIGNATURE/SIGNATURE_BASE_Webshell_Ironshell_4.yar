rule SIGNATURE_BASE_Webshell_Ironshell_4
{
	meta:
		description = "PHP Webshells Github Archive - file ironshell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "06e87e02-372b-5d4e-be52-5515a068665b"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "WebShell_ironshell"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5626-L5645"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d47b8ba98ea8061404defc6b3a30839c4444a262"
		logic_hash = "1810071f261ad7390532b07ef24115726f236131aa8ffd29adbde9ebe5085e9d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<title>'.getenv(\"HTTP_HOST\").' ~ Shell I</title>" fullword
		$s2 = "$link = mysql_connect($_POST['host'], $_POST['username'], $_POST"
		$s4 = "error_reporting(0); //If there is an error, we'll show it, k?" fullword
		$s8 = "print \"<form action=\\\"\".$me.\"?p=chmod&file=\".$content.\"&d"
		$s15 = "if(!is_numeric($_POST['timelimit']))" fullword
		$s16 = "if($_POST['chars'] == \"9999\")" fullword
		$s17 = "<option value=\\\"az\\\">a - zzzzz</option>" fullword
		$s18 = "print shell_exec($command);" fullword

	condition:
		3 of them
}
