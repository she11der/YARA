rule SIGNATURE_BASE_Rootshell_Php
{
	meta:
		description = "Semi-Auto-generated  - file rootshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "aec6621e-f23a-5f9f-91f1-d2f1b1ab58d0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4290-L4303"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "265f3319075536030e59ba2f9ef3eac6"
		logic_hash = "f836dd1825dc84212d32a034c0dde45d60ccd1eb667018abb60d671b61192666"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "shells.dl.am"
		$s1 = "This server has been infected by $owner"
		$s2 = "<input type=\"submit\" value=\"Include!\" name=\"inc\"></p>"
		$s4 = "Could not write to file! (Maybe you didn't enter any text?)"

	condition:
		2 of them
}
