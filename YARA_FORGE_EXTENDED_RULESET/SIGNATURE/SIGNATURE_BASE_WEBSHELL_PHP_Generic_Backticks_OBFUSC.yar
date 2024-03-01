import "math"

rule SIGNATURE_BASE_WEBSHELL_PHP_Generic_Backticks_OBFUSC : FILE
{
	meta:
		description = "Generic PHP webshell which uses backticks directly on user input"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "5ecb329f-0755-536d-8bfa-e36158474a0b"
		date = "2021-01-07"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_webshells.yar#L2476-L2522"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "23dc299f941d98c72bd48659cdb4673f5ba93697"
		hash = "e3f393a1530a2824125ecdd6ac79d80cfb18fffb89f470d687323fb5dff0eec1"
		hash = "1e75914336b1013cc30b24d76569542447833416516af0d237c599f95b593f9b"
		hash = "8db86ad90883cd208cf86acd45e67c03f994998804441705d690cb6526614d00"
		logic_hash = "71bcd88567508aef691827bf14bbd26a9210afc88057427ecfa4071ecb74adb6"
		score = 75
		quality = 44
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$s1 = /echo[\t ]*\(?`\$/ wide ascii
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
		filesize <500 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and $s1
}
