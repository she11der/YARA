import "pe"

rule SIGNATURE_BASE_Sig_238_TELNET
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file TELNET.EXE from Windows ME"
		author = "Florian Roth (Nextron Systems)"
		id = "fae22e0f-2f69-5dc6-984c-2c07530ad11a"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L1696-L1712"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "50d02d77dc6cc4dc2674f90762a2622e861d79b1"
		logic_hash = "4e90d95b7c94933ed5c50f060840291540fc99de0173298b97d2c6ccbf75d26a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "TELNET [host [port]]" fullword wide
		$s2 = "TELNET.EXE" fullword wide
		$s4 = "Microsoft(R) Windows(R) Millennium Operating System" fullword wide
		$s14 = "Software\\Microsoft\\Telnet" fullword wide

	condition:
		all of them
}
