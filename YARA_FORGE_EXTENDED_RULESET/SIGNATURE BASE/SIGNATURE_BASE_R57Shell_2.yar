rule SIGNATURE_BASE_R57Shell_2
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "d3a3fe11-c9e1-523b-88a3-ddc0c1085d04"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L8274-L8285"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8023394542cddf8aee5dec6072ed02b5"
		logic_hash = "5319426928d33b62527efb561c2b7a226a5a473735f501b267e6b3b174972085"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "echo \"<br>\".ws(2).\"HDD Free : <b>\".view_size($free).\"</b> HDD Total : <b>\".view_"

	condition:
		all of them
}
