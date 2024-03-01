rule SIGNATURE_BASE__Nst_Php_Php_Img_Php_Php_Nstview_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files nst.php.php.txt, img.php.php.txt, nstview.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "238242f5-4e57-5edb-8806-ea5e06f1f637"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4971-L4986"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b1e13f75edbbc8f9263e0e516a54330ce57190ba0b45813dad4bafeaeefa389b"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "ddaf9f1986d17284de83a17fe5f9fd94"
		hash1 = "17a07bb84e137b8aa60f87cd6bfab748"
		hash2 = "4745d510fed4378e4b1730f56f25e569"

	strings:
		$s0 = "<tr><form method=post><td><font color=red><b>Back connect:</b></font></td><td><i"
		$s1 = "$perl_proxy_scp = \"IyEvdXNyL2Jpbi9wZXJsICANCiMhL3Vzci91c2MvcGVybC81LjAwNC9iaW4v"
		$s2 = "<tr><form method=post><td><font color=red><b>Backdoor:</b></font></td><td><input"

	condition:
		1 of them
}
