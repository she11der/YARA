rule SIGNATURE_BASE_R57Shell_3
{
	meta:
		description = "Webshells Auto-generated - file r57shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "4129d77c-2981-587b-a83e-8767dc3a48d8"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8985-L8996"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "87995a49f275b6b75abe2521e03ac2c0"
		logic_hash = "0fdca080c7ce57b7bd818a968840aebf3c5c74f188ed062fec794bfadb4e75b0"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<b>\".$_POST['cmd']"

	condition:
		all of them
}
