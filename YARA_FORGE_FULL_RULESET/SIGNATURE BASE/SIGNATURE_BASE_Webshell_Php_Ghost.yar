rule SIGNATURE_BASE_Webshell_Php_Ghost
{
	meta:
		description = "Web Shell - file ghost.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1616-L1631"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "38dc8383da0859dca82cf0c943dbf16d"
		logic_hash = "9a7635d313345e7b7cb7424726ed62015afd78412b504e406155f85c4cdf623f"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
		$s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
		$s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword

	condition:
		all of them
}
