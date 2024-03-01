rule SIGNATURE_BASE_RAT_Lostdoor
{
	meta:
		description = "Detects LostDoor RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "f86ae7a1-2182-5b2e-8f9e-9e8456f574bc"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/LostDoor"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L440-L465"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7ffa6f5cbeacca5a1e750e35d8296658d4e280078a61f94fd5f2d4b7c800bb44"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
		$a1 = "*mlt* = %"
		$a2 = "*ip* = %"
		$a3 = "*victimo* = %"
		$a4 = "*name* = %"
		$b5 = "[START]"
		$b6 = "[DATA]"
		$b7 = "We Control Your Digital World" wide ascii
		$b8 = "RC4Initialize" wide ascii
		$b9 = "RC4Decrypt" wide ascii

	condition:
		all of ($a*) or all of ($b*)
}
