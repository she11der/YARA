rule CAPE_Rhadamanthys
{
	meta:
		description = "Rhadamanthys Loader"
		author = "kevoreilly"
		id = "4683ef43-7397-5546-ae54-b4c000518182"
		date = "2023-09-18"
		modified = "2023-09-18"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/Rhadamanthys.yar#L1-L14"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "f71bee3ef1dd7b16a55397645d16c0a20d1fdd3bf662f241c0b11796629b11ff"
		score = 75
		quality = 70
		tags = ""
		cape_type = "Rhadamanthys Loader"

	strings:
		$rc4 = {88 4C 01 08 41 81 F9 00 01 00 00 7C F3 89 75 08 33 FF 8B 4D 08 3B 4D 10 72 04 83 65 08 00}
		$code = {8B 4D FC 3B CF 8B C1 74 0D 83 78 04 02 74 1C 8B 40 1C 3B C7 75 F3 3B CF 8B C1 74 57 83 78 04 17 74 09 8B 40 1C 3B C7 75 F3 EB}
		$conf = {46 BB FF 00 00 00 23 F3 0F B6 44 31 08 03 F8 23 FB 0F B6 5C 39 08 88 5C 31 08 88 44 39 08 02 C3 8B 5D 08 0F B6 C0 8A 44 08 08}
		$cape_string = "cape_options"

	condition:
		2 of them and not $cape_string
}
