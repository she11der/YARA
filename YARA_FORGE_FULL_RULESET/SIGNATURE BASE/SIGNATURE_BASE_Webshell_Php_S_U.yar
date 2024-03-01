rule SIGNATURE_BASE_Webshell_Php_S_U
{
	meta:
		description = "Web Shell - file s-u.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L364-L377"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"
		logic_hash = "3c6904fa475784e737275fd47eabea077bed57e920071c68fa09f7defecbdb72"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"

	condition:
		all of them
}
