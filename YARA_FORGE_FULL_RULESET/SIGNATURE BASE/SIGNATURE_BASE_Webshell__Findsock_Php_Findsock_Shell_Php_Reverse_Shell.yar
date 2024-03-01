rule SIGNATURE_BASE_Webshell__Findsock_Php_Findsock_Shell_Php_Reverse_Shell
{
	meta:
		description = "PHP Webshells Github Archive - from files findsock.c, php-findsock-shell.php, php-reverse-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "6567c8f1-bd7f-5844-b937-3db2d8eb7408"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7083-L7097"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2459f7114482e17f087bda4b638c29e237f2f3cb5a9e41e326ed65fc1834b6be"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "5622c9841d76617bfc3cd4cab1932d8349b7044f"
		hash1 = "4a20f36035bbae8e342aab0418134e750b881d05"
		hash2 = "40dbdc0bdf5218af50741ba011c5286a723fa9bf"

	strings:
		$s1 = "// me at pentestmonkey@pentestmonkey.net" fullword

	condition:
		all of them
}
