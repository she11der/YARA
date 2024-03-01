rule SIGNATURE_BASE_Webshell_Reader_Asp_Php
{
	meta:
		description = "PHP Webshells Github Archive - file reader.asp.php.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "80ec18e1-6f41-5188-b2d5-f4228c975fa1"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5794-L5808"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "70656f3495e2b3ad391a77d5208eec0fb9e2d931"
		logic_hash = "6ffda38584b6cdec818af8e09c62bb4a46f40230ffd5c1a68993a91c37f67680"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s5 = "ster\" name=submit> </Font> &nbsp; &nbsp; &nbsp; <a href=mailto:mailbomb@hotmail"
		$s12 = " HACKING " fullword
		$s16 = "FONT-WEIGHT: bold; BACKGROUND: #ffffff url('images/cellpic1.gif'); TEXT-INDENT: "
		$s20 = "PADDING-RIGHT: 8px; PADDING-LEFT: 8px; FONT-WEIGHT: bold; FONT-SIZE: 11px; BACKG"

	condition:
		3 of them
}
