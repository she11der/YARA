rule SIGNATURE_BASE_Webshell_PHP_Web_Kit_V3 : FILE
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		author = "Florian Roth (Nextron Systems)"
		id = "dc5fa2c9-3e1e-594d-be4f-141e1f4915f1"
		date = "2016-01-01"
		modified = "2023-12-05"
		reference = "https://github.com/wordfence/grizzly"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt29_grizzly_steppe.yar#L76-L95"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "21bf0afcd3f8de813ddfe41ef32e45806e9f9d7d3b08ae7ce65017c35e32a868"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$php = "<?php $"
		$php2 = "@assert(base64_decode($_REQUEST["
		$s1 = "(str_replace(\"\\n\", '', '"
		$s2 = "(strrev($" ascii
		$s3 = "de'.'code';" ascii

	condition:
		(( uint32(0)==0x68703f3c and $php at 0) or $php2) and filesize >8KB and filesize <100KB and all of ($s*)
}
