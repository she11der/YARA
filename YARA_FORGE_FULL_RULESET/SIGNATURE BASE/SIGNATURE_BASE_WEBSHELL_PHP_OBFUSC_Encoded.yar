import "math"

rule SIGNATURE_BASE_WEBSHELL_PHP_OBFUSC_Encoded : FILE
{
	meta:
		description = "PHP webshell obfuscated by encoding"
		author = "Arnim Rupp (https://github.com/ruppde)"
		id = "134c1189-1b41-58d5-af66-beaa4795a704"
		date = "2021-04-18"
		modified = "2023-04-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_webshells.yar#L1137-L1188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "119fc058c9c5285498a47aa271ac9a27f6ada1bf4d854ccd4b01db993d61fc52"
		hash = "d5ca3e4505ea122019ea263d6433221030b3f64460d3ce2c7d0d63ed91162175"
		hash = "8a1e2d72c82f6a846ec066d249bfa0aaf392c65149d39b7b15ba19f9adc3b339"
		logic_hash = "c2a88e48374f949fcc9c14b773f7709c96b3147d1982ae9721708474ee5a3dcd"
		score = 70
		quality = -164
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		importance = 70

	strings:
		$enc_eval1 = /(e|\\x65|\\101)(\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_eval2 = /(\\x65|\\101)(v|\\x76|\\118)(a|\\x61|\\97)(l|\\x6c|\\108)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_assert1 = /(a|\\97|\\x61)(\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
		$enc_assert2 = /(\\97|\\x61)(s|\\115|\\x73)(s|\\115|\\x73)(e|\\101|\\x65)(r|\\114|\\x72)(t|\\116|\\x74)(\(|\\x28|\\40)/ wide ascii nocase
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
		filesize <700KB and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and any of ($enc*)
}
