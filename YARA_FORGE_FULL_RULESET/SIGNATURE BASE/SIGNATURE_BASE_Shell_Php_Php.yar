rule SIGNATURE_BASE_Shell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "eaf243cb-fa26-5f34-a724-60a08acff636"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4808-L4820"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1a95f0163b6dea771da1694de13a3d8d"
		logic_hash = "dbd08e71dc512f8dcf009150fb4448cd3608291ef9078c7e6b86e6f8d820bd94"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
		$s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
		$s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword

	condition:
		1 of them
}
