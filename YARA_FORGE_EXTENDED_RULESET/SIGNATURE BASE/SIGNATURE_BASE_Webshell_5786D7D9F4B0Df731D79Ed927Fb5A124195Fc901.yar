rule SIGNATURE_BASE_Webshell_5786D7D9F4B0Df731D79Ed927Fb5A124195Fc901 : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "7958e5fc-5ac5-58bc-8128-0a778e99a4e4"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9577-L9591"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "348ccdf997965fbea791d835f1dd4e2c16d37a17ff4195e585fa4226f18faad6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b1733cbb0eb3d440c4174cc67ca693ba92308ded5fc1069ed650c3c78b1da4bc"

	strings:
		$s1 = "preg_replace(\"\\x2F\\x2E\\x2A\\x2F\\x65\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x" ascii
		$s2 = "input[type=text], input[type=password]{" fullword ascii

	condition:
		( uint16(0)==0x6c3c and filesize <80KB and all of them )
}
