import "math"

rule SIGNATURE_BASE_WEBSHELL_PHP_Includer_Tiny : FILE
{
	meta:
		description = "Suspicious: Might be PHP webshell includer, check the included file"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "9bf96ddc-d984-57eb-9803-0b01890711b5"
		date = "2021-04-17"
		modified = "2023-07-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L1897-L1942"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0687585025f99596508783b891e26d6989eec2ba"
		hash = "9e856f5cb7cb901b5003e57c528a6298341d04dc"
		hash = "b3b0274cda28292813096a5a7a3f5f77378b8905205bda7bb7e1a679a7845004"
		logic_hash = "e1efb6384009def30d845650fd0dd77319c3c7b4402cca074ca5c2a06372ab58"
		score = 75
		quality = 42
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$php_include1 = /include\(\$_(GET|POST|REQUEST)\[/ nocase wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii

	condition:
		filesize <100 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and any of ($php_include*)
}
