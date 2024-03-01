rule SIGNATURE_BASE_Rem_View_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file Rem View.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "6137434c-89e9-537b-9b26-b56178022b76"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4052-L4064"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "29420106d9a81553ef0d1ca72b9934d9"
		logic_hash = "bcd5c86e793748ffe0ce4415ee68101e8183e1f97477b49843938d254f08695a"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$php=\"/* line 1 */\\n\\n// \".mm(\"for example, uncomment next line\").\""
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 = "Welcome to phpRemoteView (RemView)"

	condition:
		1 of them
}
