rule SIGNATURE_BASE_Ru24_Post_Sh_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file ru24_post_sh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "78669d3e-629b-591a-a766-923e37d1fdba"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4742-L4754"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5b334d494564393f419af745dc1eeec7"
		logic_hash = "e81e5345bbe07ca85c94a3d8411f0dd3c418689ccae7115c098f718f9093b3bf"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "<title>Ru24PostWebShell - \".$_POST['cmd'].\"</title>" fullword
		$s3 = "if ((!$_POST['cmd']) || ($_POST['cmd']==\"\")) { $_POST['cmd']=\"id;pwd;uname -a"
		$s4 = "Writed by DreAmeRz" fullword

	condition:
		1 of them
}
