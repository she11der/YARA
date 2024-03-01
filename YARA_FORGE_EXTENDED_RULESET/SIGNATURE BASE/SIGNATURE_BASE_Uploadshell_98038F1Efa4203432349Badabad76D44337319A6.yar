rule SIGNATURE_BASE_Uploadshell_98038F1Efa4203432349Badabad76D44337319A6 : FILE
{
	meta:
		description = "Detects a web shell"
		author = "Florian Roth (Nextron Systems)"
		id = "f385b091-ce0d-5d5b-8eeb-57e00c8d0210"
		date = "2016-09-10"
		modified = "2023-12-05"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L9507-L9522"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "68f0de84a387a9af1a32dd8d38c66b002e16e1c954a51e6bc307580180faedbf"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"

	strings:
		$s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
		$s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
		$s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii

	condition:
		( uint16(0)==0x3f3c and filesize <6KB and ( all of ($s*))) or ( all of them )
}
