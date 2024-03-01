rule SIGNATURE_BASE_Test_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file Test.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "58d73264-6507-5560-ad3e-0cc86c2ee291"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4627-L4639"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "77e331abd03b6915c6c6c7fe999fcb50"
		logic_hash = "575a2eeadc8113d779057f98e978ed4f8914546117b57944bf65f1d6d84c9521"
		score = 50
		quality = 85
		tags = ""

	strings:
		$s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
		$s2 = "fwrite ($fp, \"$yazi\");" fullword
		$s3 = "$entry_line=\"HACKed by EntriKa\";" fullword

	condition:
		1 of them
}
