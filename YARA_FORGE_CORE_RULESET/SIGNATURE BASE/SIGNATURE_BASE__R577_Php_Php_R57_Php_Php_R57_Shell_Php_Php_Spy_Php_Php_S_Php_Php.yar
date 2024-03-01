rule SIGNATURE_BASE__R577_Php_Php_R57_Php_Php_R57_Shell_Php_Php_Spy_Php_Php_S_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files r577.php.php.txt, r57.php.php.txt, r57 Shell.php.php.txt, spy.php.php.txt, s.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "093892f6-ff53-5bd1-b7b2-fea21a9258aa"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5206-L5223"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "afbd2103b0c953d6aec070ba450f43e567560bc9743423a5731cd4d6e5e36bb6"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "0714f80f35c1fddef1f8938b8d42a4c8"
		hash1 = "eddf7a8fde1e50a7f2a817ef7cece24f"
		hash2 = "8023394542cddf8aee5dec6072ed02b5"
		hash3 = "eed14de3907c9aa2550d95550d1a2d5f"
		hash4 = "817671e1bdc85e04cc3440bbd9288800"

	strings:
		$s1 = "if(rmdir($_POST['mk_name']))"
		$s2 = "$r .= '<tr><td>'.ws(3).'<font face=Verdana size=-2><b>'.$key.'</b></font></td>"
		$s3 = "if(unlink($_POST['mk_name'])) echo \"<table width=100% cellpadding=0 cell"

	condition:
		2 of them
}
