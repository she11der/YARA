rule SIGNATURE_BASE_Mysql_Tool_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file mysql_tool.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "c67197d1-6e40-5bf2-9e1b-6ada43529435"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4654-L4666"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5fbe4d8edeb2769eda5f4add9bab901e"
		logic_hash = "9f49bd6c56c919f678ecada82ff3d801c82c98a8abdee85cda1ec7e5b6756012"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$error_text = '<strong>Failed selecting database \"'.$this->db['"
		$s1 = "$ra44  = rand(1,99999);$sj98 = \"sh-$ra44\";$ml = \"$sd98\";$a5 = $_SERV"
		$s4 = "<div align=\"center\">The backup process has now started<br "

	condition:
		1 of them
}
