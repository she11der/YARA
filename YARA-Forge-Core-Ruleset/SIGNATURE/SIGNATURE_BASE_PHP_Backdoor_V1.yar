rule SIGNATURE_BASE_PHP_Backdoor_V1
{
	meta:
		description = "Webshells Auto-generated - file PHP Backdoor v1.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f47298a9-a47c-5088-ab1f-1bd76bfd0ca8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7417-L7430"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0506ba90759d11d78befd21cabf41f3d"
		logic_hash = "396ae1ee34a06ab4863f4f54257a9020b8747fb99dff15372f0aa54fa4598e43"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
		$s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"

	condition:
		all of them
}