rule SIGNATURE_BASE_Equation_Kaspersky_Equationdruginstaller : FILE
{
	meta:
		description = "Equation Group Malware - EquationDrug installer LUTEUSOBSTOS"
		author = "Florian Roth (Nextron Systems)"
		id = "fa549e6e-f0d8-55ea-9ec9-c8ec53b55dec"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "http://goo.gl/ivt8EW"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L191-L213"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "61fab1b8451275c7fd580895d9c68e152ff46417"
		logic_hash = "815ed47a53bbc5f6c3fec3464336863028e804bde4681526ecac5de0cfff21b4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\system32\\win32k.sys" wide
		$s1 = "ALL_FIREWALLS" fullword ascii
		$x1 = "@prkMtx" fullword wide
		$x2 = "STATIC" fullword wide
		$x3 = "windir" fullword wide
		$x4 = "cnFormVoidFBC" fullword wide
		$x5 = "CcnFormSyncExFBC" fullword wide
		$x6 = "WinStaObj" fullword wide
		$x7 = "BINRES" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500000 and all of ($s*) and 5 of ($x*)
}
