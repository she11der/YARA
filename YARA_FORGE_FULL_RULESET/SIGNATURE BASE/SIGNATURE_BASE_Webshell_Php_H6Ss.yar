rule SIGNATURE_BASE_Webshell_Php_H6Ss
{
	meta:
		description = "Web Shell - file h6ss.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1161-L1174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "272dde9a4a7265d6c139287560328cd5"
		logic_hash = "c4001be111ff271335dd65c15c59da979a8e202bcf58a7f10de7f03644472153"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php eval(gzuncompress(base64_decode(\""

	condition:
		all of them
}
