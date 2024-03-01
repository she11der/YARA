rule SIGNATURE_BASE_Webshell_Php_Webshells_Phpinj
{
	meta:
		description = "PHP Webshells Github Archive - file pHpINJ.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5879-L5896"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "75116bee1ab122861b155cc1ce45a112c28b9596"
		logic_hash = "271efaa8f370376f971d3d59256658b341599ac554cc216e09401e44b16bdede"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "echo '<a href='.$expurl.'> Click Here to Exploit </a> <br />';" fullword
		$s10 = "<form action = \"<?php echo \"$_SERVER[PHP_SELF]\" ; ?>\" method = \"post\">" fullword
		$s11 = "$sql = \"0' UNION SELECT '0' , '<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 IN"
		$s13 = "Full server path to a writable file which will contain the Php Shell <br />" fullword
		$s14 = "$expurl= $url.\"?id=\".$sql ;" fullword
		$s15 = "<header>||   .::News PHP Shell Injection::.   ||</header> <br /> <br />" fullword
		$s16 = "<input type = \"submit\" value = \"Create Exploit\"> <br /> <br />" fullword

	condition:
		1 of them
}
