rule SIGNATURE_BASE_Commands
{
	meta:
		description = "Webshells Auto-generated - file commands.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "7cffefc7-4f24-5908-82a4-f11eda398377"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8249-L8261"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "174486fe844cb388e2ae3494ac2d1ec2"
		logic_hash = "5251ee090934c8f99a8a2ffef2605593943306937dc56a135a47f1da7e732587"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "If CheckRecord(\"SELECT COUNT(ID) FROM VictimDetail WHERE VictimID = \" & VictimID"
		$s2 = "proxyArr = Array (\"HTTP_X_FORWARDED_FOR\",\"HTTP_VIA\",\"HTTP_CACHE_CONTROL\",\"HTTP_F"

	condition:
		all of them
}