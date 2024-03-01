rule SIGNATURE_BASE_R57Shell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file r57shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "1f1070e8-e82c-5cae-a64a-cd5028adae97"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3845-L3858"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d28445de424594a5f14d0fe2a7c4e94f"
		logic_hash = "658eec4f3c463ec1a480bcb7ba995b8d81d1fb846832e569751d9f505f0fa87e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = " else if ($HTTP_POST_VARS['with'] == \"lynx\") { $HTTP_POST_VARS['cmd']= \"lynx "
		$s2 = "RusH security team"
		$s3 = "'ru_text12' => 'back-connect"
		$s4 = "<title>r57shell</title>"

	condition:
		1 of them
}
