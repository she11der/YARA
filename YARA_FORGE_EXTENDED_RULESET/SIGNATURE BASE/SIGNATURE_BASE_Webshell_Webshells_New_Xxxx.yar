rule SIGNATURE_BASE_Webshell_Webshells_New_Xxxx
{
	meta:
		description = "Web shells - generated from file xxxx.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L3434-L3447"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5bcba70b2137375225d8eedcde2c0ebb"
		logic_hash = "e14cc1eaf357389ca58193c77ce2f54774aebb42be9df15f12415df356c7ed42"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php eval($_POST[1]);?>  " fullword

	condition:
		all of them
}
