rule SIGNATURE_BASE_Webshell_Go_Shell
{
	meta:
		description = "PHP Webshells Github Archive - file go-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "63eaf530-050a-5db7-8885-d4a1e86d62de"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6632-L6647"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3dd85981bec33de42c04c53d081c230b5fc0e94f"
		logic_hash = "f2fcefb9a0536c80fa74ceb002e113f95de53d1f56e22c81b542c395dd11071d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "#change this password; for power security - delete this file =)" fullword
		$s2 = "if (!defined$param{cmd}){$param{cmd}=\"ls -la\"};" fullword
		$s11 = "open(FILEHANDLE, \"cd $param{dir}&&$param{cmd}|\");" fullword
		$s12 = "print << \"[kalabanga]\";" fullword
		$s13 = "<title>GO.cgi</title>" fullword

	condition:
		1 of them
}
