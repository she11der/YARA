rule SIGNATURE_BASE_Webshell_Accept_Language
{
	meta:
		description = "PHP Webshells Github Archive - file accept_language.php"
		author = "Florian Roth (Nextron Systems)"
		id = "343ed2a4-4bed-5e73-8d05-f9573b0147af"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6282-L6293"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "180b13576f8a5407ab3325671b63750adbcb62c9"
		logic_hash = "6d45071722268f5b39b1486a7dce883ecefb2b3c9993357b7b58bd603ff1c40d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "<?php passthru(getenv(\"HTTP_ACCEPT_LANGUAGE\")); echo '<br> by q1w2e3r4'; ?>" fullword

	condition:
		all of them
}
