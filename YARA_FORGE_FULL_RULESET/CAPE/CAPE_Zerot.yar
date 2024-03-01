rule CAPE_Zerot : FILE
{
	meta:
		description = "ZeroT Payload"
		author = "kevoreilly"
		id = "dc5dc18c-2ec6-541d-905c-42543f17b16d"
		date = "2019-10-30"
		modified = "2019-10-30"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/ZeroT.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "f60ae25ac3cd741b8bdc5100b5d3c474b5d9fbe8be88bfd184994bae106c3803"
		score = 75
		quality = 68
		tags = "FILE"
		cape_type = "ZeroT Payload"

	strings:
		$decrypt = {8B C1 8D B5 FC FE FF FF 33 D2 03 F1 F7 75 10 88 0C 33 41 8A 04 3A 88 06 81 F9 00 01 00 00 7C E0}
		$string1 = "(*^GF(9042&*"
		$string2 = "s2-18rg1-41g3j_.;"
		$string3 = "GET" wide
		$string4 = "open"

	condition:
		uint16(0)==0x5A4D and all of them
}
