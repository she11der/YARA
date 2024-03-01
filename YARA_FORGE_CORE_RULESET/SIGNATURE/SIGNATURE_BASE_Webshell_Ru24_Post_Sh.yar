rule SIGNATURE_BASE_Webshell_Ru24_Post_Sh
{
	meta:
		description = "PHP Webshells Github Archive - file ru24_post_sh.php"
		author = "Florian Roth (Nextron Systems)"
		id = "86a45d72-c42d-58d5-9969-d3ebfc22853d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5932-L5947"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "d2c18766a1cd4dda928c12ff7b519578ccec0769"
		logic_hash = "6cf15a67c311979d32edfb443701cef34ee32d7a672314fc7b60b262b6b2c402"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://www.ru24-team.net" fullword
		$s4 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s6 = "Ru24PostWebShell"
		$s7 = "Writed by DreAmeRz" fullword
		$s9 = "$function=passthru; // system, exec, cmd" fullword

	condition:
		1 of them
}
