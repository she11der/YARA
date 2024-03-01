rule SIGNATURE_BASE_Gen_Trojan_Mikey : FILE
{
	meta:
		description = "Trojan Mikey - file sample_mikey.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ff875436-4fed-5f20-a0a5-bfd146d93499"
		date = "2015-05-07"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_mikey_trojan.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "a8e6c3ca056b3ff2495d7728654b780735b3a4cb"
		logic_hash = "5454953bba09d6fc866bcb23ef81a0b6763d8f82b8b606597548cbb5cf6053ed"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\ERAWTFOS" fullword ascii
		$x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
		$x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE 6.00; Windows NT 5.0; MyIE 3.01)" fullword ascii
		$x3 = "%d*%u%s" fullword ascii
		$x4 = "%s %s:%d" fullword ascii
		$x5 = "Mnopqrst Vwxyabcde Ghijklm Opqrstuv Xya" fullword ascii

	condition:
		uint16(0)==0x5a4d and $s0 and 2 of ($x*)
}
