rule SIGNATURE_BASE_RAT_Punisher
{
	meta:
		description = "Detects Punisher RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "1e16b3c7-9656-5570-afa2-542367aa14d8"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Punisher"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L704-L726"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9347b8053393c3537693273c44a2a2f095928b8bc0cdcf9365a6f060d66efeb5"
		score = 75
		quality = 60
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "abccba"
		$b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
		$c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
		$d = "SpyTheSpy" wide ascii
		$e = "wireshark" wide
		$f = "apateDNS" wide
		$g = "abccbaDanabccb"

	condition:
		all of them
}
