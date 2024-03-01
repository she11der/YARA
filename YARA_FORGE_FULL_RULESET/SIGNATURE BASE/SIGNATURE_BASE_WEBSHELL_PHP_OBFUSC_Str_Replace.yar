import "math"

rule SIGNATURE_BASE_WEBSHELL_PHP_OBFUSC_Str_Replace : FILE
{
	meta:
		description = "PHP webshell which eval()s obfuscated string"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "1f5b93c9-bdeb-52c7-a99a-69869634a574"
		date = "2021-01-12"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L1345-L1400"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "691305753e26884d0f930cda0fe5231c6437de94"
		hash = "7efd463aeb5bf0120dc5f963b62463211bd9e678"
		hash = "fb655ddb90892e522ae1aaaf6cd8bde27a7f49ef"
		hash = "d1863aeca1a479462648d975773f795bb33a7af2"
		hash = "4d31d94b88e2bbd255cf501e178944425d40ee97"
		hash = "e1a2af3477d62a58f9e6431f5a4a123fb897ea80"
		logic_hash = "74fb86a7ee7342ede9f49ef004a92fb7bdf06ca62f8e8f0ea1c6adcff96bcb2d"
		score = 75
		quality = 46
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$payload1 = "str_replace" fullword wide ascii
		$payload2 = "function" fullword wide ascii
		$goto = "goto" fullword wide ascii
		$chr1 = "\\61" wide ascii
		$chr2 = "\\112" wide ascii
		$chr3 = "\\120" wide ascii
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
		filesize <300KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and any of ($payload*) and #goto>1 and (#chr1>10 or #chr2>10 or #chr3>10)
}
