rule SIGNATURE_BASE_Backdoor1_Php
{
	meta:
		description = "Semi-Auto-generated  - file backdoor1.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "89f44a1c-8a42-58f6-9308-371f4e652bff"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4342-L4354"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e1adda1f866367f52de001257b4d6c98"
		logic_hash = "7c8840dc91c16b9fa19fee16e0159a7f13db23c96596e18da0cdab07931ce35b"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
		$s2 = "class backdoor {"
		$s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"

	condition:
		1 of them
}
