rule SIGNATURE_BASE_Webshell_Php_2
{
	meta:
		description = "Web Shell - file 2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1830-L1843"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "267c37c3a285a84f541066fc5b3c1747"
		logic_hash = "bd485c825ae7ac11ff67d109d3c07fb405272a5919e00af39788d1a9c94e754d"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword

	condition:
		all of them
}
