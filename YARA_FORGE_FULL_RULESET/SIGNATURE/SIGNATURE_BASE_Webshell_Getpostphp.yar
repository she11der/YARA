rule SIGNATURE_BASE_Webshell_Getpostphp
{
	meta:
		description = "Web shells - generated from file GetPostpHp.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-03-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3554-L3567"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "20ede5b8182d952728d594e6f2bb5c76"
		logic_hash = "e75f66200593c3fdaadf1881235847f6c3f3caadcb7ffe13e8b01bce5f922702"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword

	condition:
		all of them
}
