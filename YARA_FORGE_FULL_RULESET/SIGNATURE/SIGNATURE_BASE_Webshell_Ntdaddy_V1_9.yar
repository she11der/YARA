rule SIGNATURE_BASE_Webshell_Ntdaddy_V1_9
{
	meta:
		description = "PHP Webshells Github Archive - file NTDaddy v1.9.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a175fd28-5dc2-5827-87f0-4117e889e90e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6107-L6121"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "79519aa407fff72b7510c6a63c877f2e07d7554b"
		logic_hash = "fdf8b4bb4980e588ad5ccee2d047660980d39f38617f887c5762dcdb0b858267"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "|     -obzerve : mr_o@ihateclowns.com |" fullword
		$s6 = "szTempFile = \"C:\\\" & oFileSys.GetTempName( )" fullword
		$s13 = "<form action=ntdaddy.asp method=post>" fullword
		$s17 = "response.write(\"<ERROR: THIS IS NOT A TEXT FILE>\")" fullword

	condition:
		2 of them
}
