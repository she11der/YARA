rule SIGNATURE_BASE_FSO_S_Casus15
{
	meta:
		description = "Webshells Auto-generated - file casus15.php"
		author = "Florian Roth (Nextron Systems)"
		id = "305842e4-26ad-573d-8df3-e32e239e434b"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L7549-L7560"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8d155b4239d922367af5d0a1b89533a3"
		logic_hash = "58921290952f23ff5b828d8c92c818ebd91b726cdbbc9137b0f55a0e5ca90636"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s6 = "if((is_dir(\"$deldir/$file\")) AND ($file!=\".\") AND ($file!=\"..\"))"

	condition:
		all of them
}
