rule SIGNATURE_BASE_Webshell__Small_Web_Shell_By_Zaco_Small_Zaco_Zacosmall
{
	meta:
		description = "PHP Webshells Github Archive - from files Small Web Shell by ZaCo.php, small.php, zaco.php, zacosmall.php"
		author = "Florian Roth (Nextron Systems)"
		id = "99dbcea6-7208-5bbe-b200-9ea3074d7855"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L6795-L6813"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "840c58043e39014e90e7621c1d2417d5a970c744560738abc4fea3db3cbb8d5a"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "b148ead15d34a55771894424ace2a92983351dda"
		hash1 = "e4ba288f6d46dc77b403adf7d411a280601c635b"
		hash2 = "e5713d6d231c844011e9a74175a77e8eb835c856"
		hash3 = "1b836517164c18caf2c92ee2a06c645e26936a0c"

	strings:
		$s2 = "if(!$result2)$dump_file.='#error table '.$rows[0];" fullword
		$s4 = "if(!(@mysql_select_db($db_dump,$mysql_link)))echo('DB error');" fullword
		$s6 = "header('Content-Length: '.strlen($dump_file).\"\\n\");" fullword
		$s20 = "echo('Dump for '.$db_dump.' now in '.$to_file);" fullword

	condition:
		2 of them
}
