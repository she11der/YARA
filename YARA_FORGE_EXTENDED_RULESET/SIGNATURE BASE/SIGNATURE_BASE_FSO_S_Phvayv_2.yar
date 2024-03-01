rule SIGNATURE_BASE_FSO_S_Phvayv_2
{
	meta:
		description = "Webshells Auto-generated - file phvayv.php"
		author = "Florian Roth (Nextron Systems)"
		id = "8bd52f9b-a232-566d-90ab-4085933cdc65"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L7900-L7911"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "205ecda66c443083403efb1e5c7f7878"
		logic_hash = "11418a11692412ccb309983bdadd9bda2b27b692c3282eb0386094e76c7ba1e0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"

	condition:
		all of them
}
