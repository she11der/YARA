rule SIGNATURE_BASE_Webshell_Php_Include_W_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file php-include-w-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a80ca446-6612-51b4-99a7-8a8d8e6ee196"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6530-L6543"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1a7f4868691410830ad954360950e37c582b0292"
		logic_hash = "2be144060d4fdaee38214dc2eba80c2a6fd3699060d274e66356fd5a08c9be4b"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s13 = "# dump variables (DEBUG SCRIPT) NEEDS MODIFINY FOR B64 STATUS!!" fullword
		$s17 = "\"phpshellapp\" => \"export TERM=xterm; bash -i\"," fullword
		$s19 = "else if($numhosts == 1) $strOutput .= \"On 1 host..\\n\";" fullword

	condition:
		1 of them
}
