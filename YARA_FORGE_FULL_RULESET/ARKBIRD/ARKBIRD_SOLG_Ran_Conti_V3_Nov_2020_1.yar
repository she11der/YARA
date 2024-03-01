rule ARKBIRD_SOLG_Ran_Conti_V3_Nov_2020_1 : FILE
{
	meta:
		description = "Detect Conti V3 ransomware"
		author = "Arkbird_SOLG"
		id = "89702af3-664a-5c4a-8d2b-f195f5dddb6f"
		date = "2020-12-15"
		modified = "2020-12-15"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-12-15/Conti/Ran_Conti_V3_Nov_2020_1.yar#L24-L43"
		license_url = "N/A"
		logic_hash = "2c8f2fd9b155bb4fdb1304b4d7f683bc679780d079d8bbe4fb308f94769f1392"
		score = 50
		quality = 75
		tags = "FILE"
		level = "experimental"
		hash1 = "f092b985b75a702c784f0936ce892595b91d025b26f3387a712b76dcc3a4bc81"
		hash2 = "35ccc2b71567570bcac62e2f268faca50fa95fad6ac69e74f40856eb8f9ab03d"

	strings:
		$seq1 = { 45 8c 00 8d 4d 8c c6 45 8d 7e c6 45 8e 4c c6 45 8f 0e c6 45 90 2c c6 45 91 4d c6 45 92 57 c6 45 93 13 c6 45 94 5d c6 45 95 08 c6 45 96 4c c6 45 97 77 c6 45 98 77 89 85 54 ff ff ff c6 45 99 6e 8a 45 8d e8 9f 0b 00 00 6a 6b 68 a8 21 3d be ba 0f 00 00 00 8b f0 e8 3c 3e 00 00 83 c4 08 56 ff d0 c6 45 f4 00 c6 45 f5 5a c6 45 f6 49 c6 45 f7 4c c6 45 f8 0b c6 45 f9 0b c6 45 fa 66 c6 45 fb 4c c6 45 fc 0b c6 45 fd 0b c6 45 fe 3f 89 85 50 ff ff ff 8a 45 f5 80 7d f4 00 75 2b 33 c9 66 0f 1f 84 00 00 00 00 00 8a 44 0d f5 0f b6 c0 83 e8 3f 6b c0 25 99 f7 fb 8d 42 7f 99 f7 fb 88 54 0d f5 41 83 f9 0a 72 e0 6a 6b 68 a8 21 3d be ba 0f 00 00 00 e8 bf 3d 00 00 83 c4 08 8d 4d f5 51 ff d0 c6 85 7c ff ff ff 00 8d 8d 7c ff ff ff c6 85 7d ff ff ff 48 c6 85 7e ff ff ff 17 c6 85 7f ff ff ff 3c c6 45 80 71 c6 45 81 3c c6 45 82 37 c6 45 83 57 c6 45 84 71 c6 45 85 0a c6 45 86 67 c6 45 87 12 c6 45 88 12 89 85 3c }
		$seq2 = { 6c ff ff ff 00 8d 8d 6c ff ff ff c6 85 6d ff ff ff 02 c6 85 6e ff ff ff 17 c6 85 6f ff ff ff 72 c6 85 70 ff ff ff 3a c6 85 71 ff ff ff 16 c6 85 72 ff ff ff 73 c6 85 73 ff ff ff 10 c6 85 74 ff ff ff 78 c6 85 75 ff ff ff 1c c6 85 76 ff ff ff 00 c6 85 77 ff ff ff 39 c6 85 78 ff ff ff 39 89 85 48 ff ff ff c6 85 79 ff ff ff 71 8a 85 6d ff ff ff e8 1d 08 00 00 6a 6b 68 a8 21 3d }
		$seq3 = { 8b d9 89 9d b8 fd ff ff c7 85 d4 fd ff ff 0b 01 00 00 c7 85 d8 fd ff ff 0b 02 00 00 c6 85 c4 fd ff ff 00 c6 85 c5 fd ff ff 19 c6 85 c6 fd ff ff 0d c6 85 c7 fd ff ff 27 c6 85 c8 fd ff ff 1f c6 85 c9 fd ff ff 0d c6 85 ca fd ff ff 1b c6 85 cb fd ff ff 28 c6 85 cc fd ff ff 26 c6 85 cd fd ff ff 1e c6 85 ce fd ff ff 0b c6 85 cf fd ff ff 1b c6 85 d0 fd ff ff 1b 8d 8d c4 fd ff ff c6 85 d1 fd }
		$seq4 = { c6 85 00 ff ff ff 00 c6 85 01 ff ff ff 4b c6 85 02 ff ff ff 1f c6 85 03 ff ff ff 35 c6 85 04 ff ff ff 1f c6 85 05 ff ff ff 23 c6 85 06 ff ff ff 1f c6 85 07 ff ff ff 68 c6 85 08 ff ff ff 1f c6 85 09 ff ff ff 38 c6 85 0a ff ff ff 1f c6 85 0b ff ff ff 10 c6 85 0c ff ff ff 1f c6 85 0d ff ff ff 66 c6 85 0e ff ff ff 1f c6 85 0f ff ff ff 2a c6 85 10 ff ff ff 1f c6 85 11 ff ff ff 43 c6 85 12 ff ff ff 1f c6 85 13 ff ff ff 23 c6 85 14 ff ff ff 1f c6 85 15 ff ff ff 10 c6 85 16 ff ff ff 1f c6 85 17 ff ff ff 07 c6 85 18 ff ff ff 1f c6 85 19 ff ff ff 51 c6 85 1a ff ff ff 1f c6 85 1b ff ff ff 1c c6 85 1c ff ff ff 1f c6 85 1d ff ff ff 43 c6 85 1e ff ff ff 1f c6 85 1f ff ff ff 10 c6 85 20 ff ff ff 1f c6 85 21 ff ff ff 61 c6 85 22 ff ff ff 1f c6 85 23 ff ff ff 74 c6 85 24 ff ff ff 1f c6 85 25 ff ff ff 41 c6 85 26 ff ff ff 1f c6 85 27 ff ff ff 10 c6 85 28 ff ff ff 1f c6 85 29 ff ff ff 59 c6 85 2a ff ff ff 1f c6 85 2b ff ff ff 43 c6 85 2c ff ff ff 1f c6 85 2d ff ff ff 38 c6 85 2e ff ff ff 1f c6 85 2f ff ff ff 2b c6 85 30 }

	condition:
		uint16(0)==0x5a4d and filesize >80KB and all of ($seq*)
}
