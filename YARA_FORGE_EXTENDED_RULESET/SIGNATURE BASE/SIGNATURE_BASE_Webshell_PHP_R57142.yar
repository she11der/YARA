rule SIGNATURE_BASE_Webshell_PHP_R57142
{
	meta:
		description = "Web Shell - file r57142.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1392-L1405"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
		logic_hash = "3afa0463de3acb12480dba1b2ab9cd53fca88216ba54c5e044e48ebd84bf17bd"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword

	condition:
		all of them
}
