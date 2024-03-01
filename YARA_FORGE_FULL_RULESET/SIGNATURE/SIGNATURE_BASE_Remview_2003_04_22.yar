rule SIGNATURE_BASE_Remview_2003_04_22
{
	meta:
		description = "Webshells Auto-generated - file remview_2003_04_22.php"
		author = "Florian Roth (Nextron Systems)"
		id = "3088ee27-42a3-5140-98de-ab6f87c7748b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8313-L8324"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "17d3e4e39fbca857344a7650f7ea55e3"
		logic_hash = "2957f6ec7a022ac04759724276f6928625708346903597b0765b5e81207fc6b9"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""

	condition:
		all of them
}
