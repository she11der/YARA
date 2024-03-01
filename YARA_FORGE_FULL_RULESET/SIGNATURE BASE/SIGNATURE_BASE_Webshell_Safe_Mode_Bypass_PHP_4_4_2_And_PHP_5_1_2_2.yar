rule SIGNATURE_BASE_Webshell_Safe_Mode_Bypass_PHP_4_4_2_And_PHP_5_1_2_2
{
	meta:
		description = "PHP Webshells Github Archive - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		author = "Florian Roth (Nextron Systems)"
		id = "a504442f-85f2-55a1-8a07-1e0faccf8bc0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6092-L6106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8fdd4e0e87c044177e9e1c97084eb5b18e2f1c25"
		logic_hash = "fbe1f77e00fbc4e58cbad564e2d96c0381765ac799dfdf6cc2580428c68f97a5"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "<option value=\"/etc/passwd\">Get /etc/passwd</option>" fullword
		$s3 = "xb5@hotmail.com</FONT></CENTER></B>\");" fullword
		$s4 = "$v = @ini_get(\"open_basedir\");" fullword
		$s6 = "by PHP Emperor<xb5@hotmail.com>" fullword

	condition:
		2 of them
}
