rule SIGNATURE_BASE_Webshell_Zehir4_Asp_Php
{
	meta:
		description = "PHP Webshells Github Archive - file zehir4.asp.php.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "7a849bc6-fff5-5bb6-aff7-660889fd077b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6678-L6691"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1d9b78b5b14b821139541cc0deb4cbbd994ce157"
		logic_hash = "dfaf685ac3b364143bfbe289b05f066b09f01622fec3e9157f4b4791f7567619"
		score = 75
		quality = 60
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s4 = "response.Write \"<title>zehir3 --> powered by zehir &lt;zehirhacker@hotmail.com&"
		$s11 = "frames.byZehir.document.execCommand("
		$s15 = "frames.byZehir.document.execCommand(co"

	condition:
		2 of them
}
