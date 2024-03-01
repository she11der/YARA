rule SIGNATURE_BASE_Webshell_Phpshell3
{
	meta:
		description = "Web Shell - file phpshell3.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L549-L564"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "76117b2ee4a7ac06832d50b2d04070b8"
		logic_hash = "868b1b69fab3ec6fcfa15557075f313f4af0ec9cd15f41bb9dcc9bc26fc17f93"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
		$s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
		$s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword

	condition:
		2 of them
}
