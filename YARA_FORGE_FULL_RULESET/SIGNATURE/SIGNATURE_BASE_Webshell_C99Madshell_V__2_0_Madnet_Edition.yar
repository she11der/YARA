rule SIGNATURE_BASE_Webshell_C99Madshell_V__2_0_Madnet_Edition
{
	meta:
		description = "PHP Webshells Github Archive - file C99madShell v. 2.0 madnet edition.php"
		author = "Florian Roth (Nextron Systems)"
		id = "51db0495-14f3-527e-865b-1405db57ff27"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L6169-L6184"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f99f8228eb12746847f54bad45084f19d1a7e111"
		logic_hash = "7cf825a604783ebc74b1dca53aaff5c886957c562e11276f2acce5ff1f6ab991"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$md5_pass = \"\"; //If no pass then hash" fullword
		$s1 = "eval(gzinflate(base64_decode('"
		$s2 = "$pass = \"\";  //Pass" fullword
		$s3 = "$login = \"\"; //Login" fullword
		$s4 = "//Authentication" fullword

	condition:
		all of them
}
