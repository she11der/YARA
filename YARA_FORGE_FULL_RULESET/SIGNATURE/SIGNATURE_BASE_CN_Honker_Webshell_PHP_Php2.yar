rule SIGNATURE_BASE_CN_Honker_Webshell_PHP_Php2 : FILE
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file php2.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "377ff89d-a9ba-526c-97a1-388f9ccb48ba"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_webshells.yar#L476-L491"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bf12e1d741075cd1bd324a143ec26c732a241dea"
		logic_hash = "707e2795d82636fbbc4d9f5324e509a526f77f9ead8f3c4d59dd0e95bc94f11e"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$OOO0O0O00=__FILE__;$OOO000000=urldecode('" ascii
		$s2 = "<?php // Black" fullword ascii

	condition:
		filesize <12KB and all of them
}
