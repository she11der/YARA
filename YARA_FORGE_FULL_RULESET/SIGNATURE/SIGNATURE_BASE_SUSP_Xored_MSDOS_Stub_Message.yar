rule SIGNATURE_BASE_SUSP_Xored_MSDOS_Stub_Message : FILE
{
	meta:
		description = "Detects suspicious XORed MSDOS stub message"
		author = "Florian Roth"
		id = "9ab52434-9162-5fd5-bf34-8b163f6aeec4"
		date = "2019-10-28"
		modified = "2023-10-11"
		reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_xor_hunting.yar#L22-L51"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b6d7d7242511d2c26122fe2b880cfe39facb5f68ae45e19c1558163f0427c304"
		score = 55
		quality = 85
		tags = "FILE"

	strings:
		$xo1 = "This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
		$xo2 = "This program must be run under Win32" xor(0x01-0xff) ascii wide
		$fp1 = "AVAST Software" fullword wide ascii
		$fp2 = "AVG Netherlands" fullword wide ascii
		$fp3 = "AVG Technologies" ascii wide
		$fp4 = "Malicious Software Removal Tool" wide
		$fp5 = "McAfee Labs" fullword ascii wide
		$fp6 = "Kaspersky Lab" fullword ascii wide
		$fp7 = "<propertiesmap>" ascii wide
		$fp10 = "Avira Engine Module" wide
		$fp11 = "syntevo GmbH" wide fullword
		$fp13 = "SophosClean" ascii
		$fp14 = "SophosHomeClean" wide

	condition:
		1 of ($x*) and not 1 of ($fp*) and not uint16(0)==0xb0b0 and not uint16(0)==0x5953
}
