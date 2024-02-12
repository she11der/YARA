rule SIGNATURE_BASE_PHP_Sh
{
	meta:
		description = "Webshells Auto-generated - file sh.php"
		author = "Florian Roth (Nextron Systems)"
		id = "08dff4db-3b1c-5702-a8c9-efaedf83c4ff"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8479-L8490"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "1e9e879d49eb0634871e9b36f99fe528"
		logic_hash = "da0b572f116cc5c55e8d7469f222896d602d09be4761a0e2139fc8ce67ac4050"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\"@$SERVER_NAME \".exec(\"pwd\")"

	condition:
		all of them
}