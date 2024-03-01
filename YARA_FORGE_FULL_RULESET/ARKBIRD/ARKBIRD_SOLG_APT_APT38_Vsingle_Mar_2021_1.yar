rule ARKBIRD_SOLG_APT_APT38_Vsingle_Mar_2021_1 : FILE
{
	meta:
		description = "Detect VSingle used in attacks against Japanese organisations by APT38"
		author = "Arkbird_SOLG"
		id = "d1d640f6-bcec-5364-8ea5-e0c0b86da6e1"
		date = "2021-03-23"
		modified = "2021-03-24"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-03-23/APT38/APT_APT38_VSingle_Mar_2021_1.yar#L1-L24"
		license_url = "N/A"
		logic_hash = "d01baac099ce33b837c83d6778900f7e55b8c63e75d0e552c10ababc8dec744c"
		score = 50
		quality = 69
		tags = "FILE"
		hash1 = "487c1bdb65634a794fa5e359c383c94945ce9f0806fcad46440e919ba0e6166e"
		level = "experimental"

	strings:
		$dbg1 = { 68 74 74 70 [0-1] 3a 2f 2f 25 73 25 73 }
		$dbg2 = { 43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 20 66 69 6e 69 73 68 65 64 20 77 69 74 68 20 45 72 72 6f 72 2d 25 64 }
		$dbg3 = { 4f 53 3a 20 25 73 25 73 20 53 50 20 25 64 20 25 73 20 28 25 64 2e 25 64 2e 25 64 29 0d 0a }
		$dbg4 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 75 00 20 00 2f 00 63 00 20 00 25 00 73 }
		$dbg5 = { 0d 0a 43 6f 6f 6b 69 65 3a 20 25 73 }
		$dbg6 = { 25 73 5f 6d 61 69 6e }
		$dbg7 = { 25 73 5f 66 69 6e }
		$dbg8 = "3%3*373<3I3N3[3`3m3r3" fullword ascii
		$s1 = { 8b 8d 80 f8 ff ff c7 41 04 01 00 00 00 83 e8 01 0f 84 aa 12 00 00 83 e8 01 0f 84 9a 12 00 00 83 e8 01 0f 84 8a 12 00 00 83 e8 01 0f 84 7a 12 00 }
		$s2 = { 51 83 7d 08 00 75 07 b8 5b ab 66 00 eb 35 8b 45 08 89 45 fc 8b 4d fc }

	condition:
		uint16(0)==0x5a4d and filesize >30KB and 6 of ($dbg*) and all of ($s*)
}
