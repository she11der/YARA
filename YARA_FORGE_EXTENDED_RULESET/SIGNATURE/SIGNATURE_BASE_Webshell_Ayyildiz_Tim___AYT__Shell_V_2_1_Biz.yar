rule SIGNATURE_BASE_Webshell_Ayyildiz_Tim___AYT__Shell_V_2_1_Biz
{
	meta:
		description = "PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php"
		author = "Florian Roth (Nextron Systems)"
		id = "fdd9bae9-80f3-5200-b922-e7d194009af8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6403-L6417"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68"
		logic_hash = "2d096baad162c0e3e01732007a3be2804155e614a8fa4cd2d5dd3a7ac808fb49"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
		$s11 = "directory... Trust me - it works :-) */" fullword
		$s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
		$s16 = "} else if ($command == 'ls') {" fullword

	condition:
		3 of them
}
