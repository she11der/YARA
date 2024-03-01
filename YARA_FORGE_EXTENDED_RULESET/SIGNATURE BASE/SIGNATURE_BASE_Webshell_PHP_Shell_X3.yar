rule SIGNATURE_BASE_Webshell_PHP_Shell_X3
{
	meta:
		description = "Web Shell - file PHP Shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1130-L1145"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
		logic_hash = "7361a7eecf345b9c1809294b6b081db8769805ec3e6c656adc4ac87261193683"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("

	condition:
		2 of them
}
