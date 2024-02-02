rule SIGNATURE_BASE__Antichat_Php_Php_Fatalshell_Php_Php_A_Gedit_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - from files antichat.php.php.txt, Fatalshell.php.php.txt, a_gedit.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "6bf5640f-0773-5d93-8d27-0844062017c7"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5350-L5366"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "789340845aeed4accaef02afa1a1fe420e73b6f5af1b621f4ec2342994045278"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "128e90b5e2df97e21e96d8e268cde7e3"
		hash1 = "b15583f4eaad10a25ef53ab451a4a26d"
		hash2 = "ab9c6b24ca15f4a1b7086cad78ff0f78"

	strings:
		$s0 = "if(@$_POST['save'])writef($file,$_POST['data']);" fullword
		$s1 = "if($action==\"phpeval\"){" fullword
		$s2 = "$uploadfile = $dirupload.\"/\".$_POST['filename'];" fullword
		$s3 = "$dir=getcwd().\"/\";" fullword

	condition:
		2 of them
}