rule CAPE_Asyncrat : FILE
{
	meta:
		description = "AsyncRat Payload"
		author = "kevoreilly, JPCERT/CC Incident Response Group"
		id = "478557fa-2418-5b13-99d9-2395ce83b9a2"
		date = "2022-03-09"
		modified = "2022-03-09"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/AsyncRat.yar#L1-L17"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "8f960131bb86e1c09127324bd5877364ab25e0cb37f5f9755230c7fed9094de3"
		score = 75
		quality = 66
		tags = "FILE"
		cape_type = "AsyncRat Payload"

	strings:
		$salt = {BF EB 1E 56 FB CD 97 3B B2 19 02 24 30 A5 78 43 00 3D 56 44 D2 1E 62 B9 D4 F1 80 E7 E6 C3 39 41}
		$b1 = {00 00 00 0D 53 00 48 00 41 00 32 00 35 00 36 00 00}
		$b2 = {09 50 00 6F 00 6E 00 67 00 00}
		$string1 = "Pastebin" ascii wide nocase
		$string2 = "Pong" wide
		$string3 = "Stub.exe" ascii wide
		$kitty = "StormKitty" ascii

	condition:
		uint16(0)==0x5A4D and not $kitty and ($salt and (2 of ($str*) or 1 of ($b*))) or ( all of ($b*) and 2 of ($str*))
}
