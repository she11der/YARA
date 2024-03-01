rule CAPE_Icedid
{
	meta:
		description = "IcedID Payload"
		author = "kevoreilly, threathive"
		id = "439342be-a1e6-5656-8813-5cebb0e88e98"
		date = "2021-12-16"
		modified = "2021-12-16"
		reference = "https://github.com/kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/data/yara/CAPE/IcedID.yar#L1-L18"
		license_url = "https://github.com/kevoreilly/CAPEv2/blob/ef54cd63832eb05a5e502bbd6dd9217938d66a5d/LICENSE"
		logic_hash = "e60ccbab7a360020744eba65961156ca3e2ae9cf23671014f913d71c1a96a331"
		score = 75
		quality = 45
		tags = ""
		cape_type = "IcedID Payload"

	strings:
		$crypt1 = {8A 04 ?? D1 C? F7 D? D1 C? 81 E? 20 01 00 00 D1 C? F7 D? 81 E? 01 91 00 00 32 C? 88}
		$crypt2 = {8B 44 24 04 D1 C8 F7 D0 D1 C8 2D 20 01 00 00 D1 C0 F7 D0 2D 01 91 00 00 C3}
		$crypt3 = {41 00 8B C8 C1 E1 08 0F B6 C4 66 33 C8 66 89 4? 24 A1 ?? ?? 41 00 89 4? 20 A0 ?? ?? 41 00 D0 E8 32 4? 32}
		$download1 = {8D 44 24 40 50 8D 84 24 44 03 00 00 68 04 21 40 00 50 FF D5 8D 84 24 4C 01 00 00 C7 44 24 28 01 00 00 00 89 44 24 1C 8D 4C 24 1C 8D 84 24 4C 03 00 00 83 C4 0C 89 44 24 14 8B D3 B8 BB 01 00 00 66 89 44 24 18 57}
		$download2 = {8B 75 ?? 8D 4D ?? 8B 7D ?? 8B D6 57 89 1E 89 1F E8 [4] 59 3D C8 00 00 00 75 05 33 C0 40 EB}
		$major_ver = {0F B6 05 ?? ?? ?? ?? 6A ?? 6A 72 FF 75 0C 6A 70 50 FF 35 ?? ?? ?? ?? 8D 45 80 FF 35 ?? ?? ?? ?? 6A 63 FF 75 08 6A 67 50 FF 75 10 FF 15 ?? ?? ?? ?? 83 C4 38 8B E5 5D C3}
		$stage_2_request_binary = "id="
		$stage_2_request_img = ".png"

	condition:
		any of ($crypt*,$download*,$major_ver) and all of ($stage_2_request_*)
}
