rule SIGNATURE_BASE_Xssshell_Db
{
	meta:
		description = "Webshells Auto-generated - file db.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "94bb2297-95a2-5442-bb16-fb079a29606e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8467-L8478"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"
		logic_hash = "3fdbaa17c12abef8576bf859065d90f4b6e80c187af734b71b26a1bd5d073e86"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"

	condition:
		all of them
}
