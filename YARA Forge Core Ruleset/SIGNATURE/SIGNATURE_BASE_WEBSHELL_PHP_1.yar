rule SIGNATURE_BASE_WEBSHELL_PHP_1
{
	meta:
		description = "Webshells Auto-generated - file phpshell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "d0107af3-e484-54cf-a238-dd1e71efd3f6"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "phpshell"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7661-L7675"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "1dccb1ea9f24ffbd085571c88585517b"
		logic_hash = "eed450ae6668bbee01ea2689e9864f10a66714ec4c91afabb12609ad4ebdac8c"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "echo \"<input size=\\\"100\\\" type=\\\"text\\\" name=\\\"newfile\\\" value=\\\"$inputfile\\\"><b"
		$s2 = "$img[$id] = \"<img height=\\\"16\\\" width=\\\"16\\\" border=\\\"0\\\" src=\\\"$REMOTE_IMAGE_UR"
		$s3 = "$file = str_replace(\"\\\\\", \"/\", str_replace(\"//\", \"/\", str_replace(\"\\\\\\\\\", \"\\\\\", "

	condition:
		all of them
}