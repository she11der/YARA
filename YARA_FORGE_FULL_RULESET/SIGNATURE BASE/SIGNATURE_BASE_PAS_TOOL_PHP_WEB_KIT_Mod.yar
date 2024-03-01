rule SIGNATURE_BASE_PAS_TOOL_PHP_WEB_KIT_Mod : FILE
{
	meta:
		description = "Detects PAS Tool PHP Web Kit"
		author = "US CERT - modified by Florian Roth due to performance reasons"
		id = "6bc75e44-7784-5e48-9bbc-052d84ebee83"
		date = "2016-12-29"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/security-publications/GRIZZLY-STEPPE-Russian-Malicious-Cyber-Activity"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt29_grizzly_steppe.yar#L52-L74"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "fab894d9609c1fca4a85457e6799d082dfd3eb9ca0564abc04a1a0dd07a7b546"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$php = "<?php"
		$base64decode1 = "='base'.("
		$strreplace = "str_replace(\"\\n\", ''"
		$md5 = ".substr(md5(strrev("
		$gzinflate = "gzinflate"
		$cookie = "_COOKIE"
		$isset = "isset"

	condition:
		uint32(0)==0x68703f3c and $php at 0 and ( filesize >10KB and filesize <30KB) and #cookie==2 and #isset==3 and all of them
}
