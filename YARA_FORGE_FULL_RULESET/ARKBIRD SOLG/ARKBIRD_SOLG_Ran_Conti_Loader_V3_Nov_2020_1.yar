rule ARKBIRD_SOLG_Ran_Conti_Loader_V3_Nov_2020_1 : FILE
{
	meta:
		description = "Detect Conti V3 loader"
		author = "Arkbird_SOLG"
		id = "9541b9f8-befe-5bf4-88ee-b1cc5e92f927"
		date = "2020-12-15"
		modified = "2020-12-15"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-15/Conti/Ran_Conti_V3_Nov_2020_1.yar#L1-L22"
		license_url = "N/A"
		logic_hash = "c3c8530e1963c5af8ee93a5d2cc222abbeb3fb7e82ef6de2068795a38dca67aa"
		score = 50
		quality = 71
		tags = "FILE"
		level = "experimental"
		hash1 = "707b752f6bd89d4f97d08602d0546a56d27acfe00e6d5df2a2cb67c5e2eeee30"
		hash2 = "26b2401211769d2fa1415228b4b1305eeeed249a996d149ad83b6fc9c4f703ce"

	strings:
		$seq1 = { 83 ec 1c 68 80 00 00 00 68 54 21 40 00 ff 15 30 20 40 00 85 c0 0f 85 e9 00 00 00 56 57 68 48 21 40 00 89 44 24 14 89 44 24 10 c7 44 24 1c 17 00 00 00 c7 44 24 20 55 1e 00 00 c7 44 24 24 09 04 00 00 ff 15 34 20 40 00 8b 3d 3c 20 40 00 8b f0 68 34 21 40 00 56 ff d7 68 20 21 40 00 56 a3 e4 33 40 00 ff d7 a3 0c 36 40 00 8d 44 24 14 50 6a 03 8d 4c 24 20 51 68 00 00 40 00 ff 15 e4 33 40 00 85 c0 7c 1a 8b 4c 24 14 8d 54 24 0c 52 8d 44 24 14 50 51 68 00 00 40 00 ff 15 0c 36 40 00 68 18 21 40 00 ff 15 70 20 40 00 8b 54 24 10 83 c4 04 50 68 00 10 00 00 52 6a 00 ff 15 38 20 40 00 8b 4c 24 10 8b f0 8b 44 24 0c 50 51 56 e8 4a 00 00 00 8d 54 24 14 52 }
		$seq2 = { 8b 4c 24 24 8d 44 24 20 50 51 56 e8 1d fe ff ff 83 c4 24 ff d6 8b 54 24 28 5f 89 15 08 36 40 00 5e 33 c0 83 c4 }
		$s1 = { 3e 35 44 35 4c 35 53 35 58 35 5e 35 64 35 6c 35 72 35 79 35 }
		$s2 = { 31 07 32 0d 32 25 32 2b 32 30 32 36 32 4c 32 6a 32 }
		$s3 = "_invoke_watson" fullword ascii
		$s4 = { 8b 2d bc 36 40 00 0f b6 04 2f 0f b6 da 8b 54 24 14 0f b6 14 13 8d 0c 2f 03 d6 03 c2 99 be 40 03 00 00 f7 fe 0f b6 f2 8d 04 2e e8 7f ff ff ff 8d 43 01 99 f7 7c 24 18 47 81 ff 40 }

	condition:
		uint16(0)==0x5a4d and filesize >100KB and all of ($seq*) and 2 of ($s*)
}
