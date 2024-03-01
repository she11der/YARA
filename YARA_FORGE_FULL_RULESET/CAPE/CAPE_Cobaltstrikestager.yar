rule CAPE_Cobaltstrikestager
{
	meta:
		description = "Cobalt Strike Stager Payload"
		author = "@dan__mayer <daniel@stairwell.com>"
		id = "eedf71b1-9f27-5a6f-afe8-3ddae47f9a06"
		date = "2023-01-18"
		modified = "2023-01-18"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/CobaltStrikeStager.yar#L1-L15"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "6a55b0c3ab5f557dfb7a3f8bd616ede1bd9b93198590fc9d52aa19c1154388c5"
		score = 75
		quality = 70
		tags = ""
		cape_type = "CobaltStrikeStager Payload"

	strings:
		$smb = { 68 00 B0 04 00 68 00 B0 04 00 6A 01 6A 06 6A 03 52 68 45 70 DF D4 }
		$http_x86 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }
		$http_x64 = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 49 89 E6 4C 89 F1 41 BA 4C 77 26 07 }
		$dns = { 68 00 10 00 00 68 FF FF 07 00 6A 00 68 58 A4 53 E5 }

	condition:
		any of them
}
