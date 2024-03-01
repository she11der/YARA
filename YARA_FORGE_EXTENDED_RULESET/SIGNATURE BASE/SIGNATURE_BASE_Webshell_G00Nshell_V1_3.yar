rule SIGNATURE_BASE_Webshell_G00Nshell_V1_3
{
	meta:
		description = "PHP Webshells Github Archive - file g00nshell-v1.3.php"
		author = "Florian Roth (Nextron Systems)"
		id = "61a09576-7e62-5a30-a52c-492b81b96322"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6465-L6480"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "70fe072e120249c9e2f0a8e9019f984aea84a504"
		logic_hash = "2ecb3ce2aa43a99552fb26e610c35bdb04f4ff0dc75c867e4327d6e27eed0177"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s10 = "#To execute commands, simply include ?cmd=___ in the url. #" fullword
		$s15 = "$query = \"SHOW COLUMNS FROM \" . $_GET['table'];" fullword
		$s16 = "$uakey = \"724ea055b975621b9d679f7077257bd9\"; // MD5 encoded user-agent" fullword
		$s17 = "echo(\"<form method='GET' name='shell'>\");" fullword
		$s18 = "echo(\"<form method='post' action='?act=sql'>\");" fullword

	condition:
		2 of them
}
