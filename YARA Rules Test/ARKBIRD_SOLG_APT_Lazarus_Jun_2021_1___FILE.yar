rule ARKBIRD_SOLG_APT_Lazarus_Jun_2021_1___FILE
{
	meta:
		description = "Detect a variant of NukeSped malware"
		author = "Arkbird_SOLG"
		id = "0f5d42c0-d6dc-573b-9227-787ccbcaa83d"
		date = "2021-06-19"
		modified = "2021-06-21"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-06-19/Lazarus/APT_Lazarus_Jun_2021_1.yara#L1-L20"
		license_url = "N/A"
		logic_hash = "ea4ce93d54b9b8e5d1d5bb64d37ac26839e2fa3200da3057597d83c4be6d129f"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "5c2f339362d0cd8e5a8e3105c9c56971087bea2701ea3b7324771b0ea2c26c6c"
		hash2 = "2dff6d721af21db7d37fc1bd8b673ec07b7114737f4df2fa8b2ecfffbe608a00"
		hash3 = "1177105e51fa02f9977bd435f9066123ace32b991ed54912ece8f3d4fbeeade4"
		tlp = "White"
		adversary = "Lazarus"

	strings:
		$seq1 = { 48 8b ce e8 8a 2c 00 00 48 8b d8 48 85 c0 0f 84 28 06 00 00 4c 8b c6 33 d2 48 8b c8 e8 11 56 00 00 8d 4e fc 48 8d 57 04 4c 63 c1 48 8b cb e8 af 3a 00 00 33 c0 48 8d 4c 24 30 48 89 4c 24 28 45 33 c9 4c 8b c3 33 d2 33 c9 89 44 24 30 89 44 24 20 ff 15 4b 49 01 00 48 85 c0 0f 84 d4 05 00 00 ba 88 13 00 00 48 8b c8 ff 15 9c 2c 02 00 48 8d 8d 91 00 00 00 33 d2 41 b8 ff 03 00 00 c6 85 90 00 00 00 00 e8 a9 55 00 00 48 8d 15 02 c1 01 00 48 8d 8d 90 00 00 00 e8 16 2b 00 00 48 8d 85 90 00 00 00 48 83 cb ff 48 ff c3 80 3c 18 00 75 f7 41 b2 84 ba 43 90 21 57 41 b8 c2 a2 a9 09 85 db 0f 8e 4b 05 00 00 4c 8d 8d 90 00 00 00 44 8b db 66 90 41 0f b6 01 41 0f b6 c8 4d 8d 49 01 32 ca 41 32 c2 44 22 d1 41 32 c0 42 8d 0c c5 00 00 00 00 32 c2 41 33 c8 41 88 41 ff 81 e1 f8 07 00 00 41 0f b6 c0 22 c2 c1 e1 14 44 32 d0 41 8b c0 44 8b c1 c1 e8 08 8d 0c 12 33 ca 44 0b c0 8b c2 c1 e1 04 c1 e0 07 33 ca 83 e1 80 33 c8 8b c2 c1 e1 11 c1 e8 08 8b d1 0b d0 49 ff }
		$seq2 = { 48 8d ac 24 50 ff ff ff 48 81 ec b0 01 00 00 48 8b 05 82 09 02 00 48 33 c4 48 89 85 a0 00 00 00 44 8b 25 d5 38 02 00 4c 8b f9 48 8d 4d 91 33 d2 41 b8 03 01 00 00 c6 45 90 00 e8 59 66 00 00 b9 3c 00 00 00 ff 15 f6 3c 02 00 ff 15 88 59 01 00 8b c8 e8 51 42 00 00 e8 20 42 00 00 b9 3c 00 00 00 8b d8 83 e3 03 83 c3 08 ff 15 d1 3c 02 00 ff 15 63 59 01 00 8b c8 e8 2c 42 00 00 e8 fb 41 00 00 b9 3c 00 00 00 8b f8 83 e7 01 83 c7 05 ff 15 ac 3c 02 00 ff 15 3e 59 01 00 8b c8 e8 07 42 00 00 e8 d6 41 00 00 8b f0 b8 ab aa aa aa f7 e6 d1 ea 8d 0c 52 2b f1 83 eb 08 0f 84 30 03 00 00 ff cb 0f 84 68 02 00 00 ff cb 0f 84 9a 01 00 00 ff cb 0f 85 ef 04 00 00 8d 4b 3c ff 15 60 3c 02 00 ff 15 f2 58 01 00 8b c8 e8 bb 41 00 00 e8 8a 41 00 00 8b d8 b8 1f 85 eb 51 f7 e3 c1 ea 03 6b ca 19 2b d9 b9 3c 00 00 00 83 c3 0a ff 15 2f 3c 02 00 ff 15 c1 58 01 00 8b c8 e8 8a 41 00 00 e8 59 41 00 00 44 8b f0 b8 ab aa aa aa 41 f7 e6 c1 ea 02 8d 0c 52 03 c9 44 2b f1 b9 3c 00 00 00 41 81 c6 d7 07 00 00 ff 15 f5 3b 02 00 ff 15 87 58 01 00 8b c8 e8 50 41 00 00 e8 1f 41 00 00 44 8b e8 b8 ab aa aa aa 41 f7 e5 c1 ea 03 8d 0c 52 c1 e1 02 44 2b e9 b9 3c 00 00 00 41 ff c5 ff 15 be 3b 02 00 ff 15 50 58 01 00 8b c8 e8 19 41 00 00 e8 e8 40 00 00 44 8b c0 b8 09 cb 3d 8d 41 f7 e0 c1 ea 04 6b ca 1d 44 2b c1 b9 7d 00 00 00 41 ff c0 44 89 44 24 74 e8 3e 3b 00 00 33 d2 44 8d 42 7d 48 8b c8 e8 d0 64 00 00 4c 8d 44 24 70 48 8d 0d d4 ce 01 00 ba 7c 00 00 00 c7 44 24 70 00 00 00 00 e8 c2 27 00 00 44 8b 44 24 70 48 8b d0 48 8b c8 48 89 44 24 78 e8 3d 25 00 00 48 8b 44 24 78 4c 8d 45 90 48 8b d0 4c 2b c0 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 0f b6 0a 48 8d 52 01 41 88 4c 10 ff 84 c9 75 f0 48 8b c8 e8 88 3a 00 00 8b 44 24 74 44 89 64 24 48 89 5c 24 40 89 44 24 38 44 89 6c 24 30 48 8d 55 90 44 8b cf 41 b8 04 00 00 00 49 8b cf 44 89 74 24 28 89 74 24 20 e8 b4 39 00 00 e9 5d 03 00 00 b9 3c 00 00 00 ff 15 cc 3a 02 00 ff 15 5e 57 01 00 8b c8 e8 27 40 00 00 e8 f6 3f 00 00 b9 79 00 00 00 8b d8 83 e3 03 e8 63 3a 00 00 33 d2 44 8d 42 79 48 8b c8 e8 f5 63 00 00 4c 8d 44 24 70 48 8d 0d 79 cd 01 00 ba 78 00 00 00 c7 44 24 70 00 00 00 00 e8 e7 26 00 00 44 8b 44 24 70 48 8b d0 48 8b c8 4c 8b f0 e8 64 24 00 00 4c 8d 45 90 49 8b d6 4d 2b c6 66 66 0f 1f 84 00 00 00 00 00 0f b6 0a 48 8d 52 01 41 88 4c 10 ff 84 c9 75 f0 49 8b ce e8 b8 39 00 00 44 89 64 24 38 8d 43 04 89 44 24 30 44 8d 4b 08 48 8d 55 90 41 b8 04 00 00 00 49 8b cf 89 74 24 28 89 }
		$seq3 = { 48 89 5c 24 18 55 56 57 48 83 ec 70 48 8b 05 9d fe 01 00 48 33 c4 48 89 44 24 60 33 c0 48 8b d9 8b fa 8d 48 20 c6 44 24 48 00 48 89 44 24 49 48 89 44 24 51 e8 d7 31 00 00 48 8d 15 44 c6 01 00 48 8b f0 33 c0 48 8d 4c 24 48 48 89 06 48 89 46 08 48 89 46 10 4c 8b c3 48 89 46 18 e8 3f 13 00 00 48 8d 4c 24 48 ff 15 ac 50 01 00 bd 02 00 00 00 0f b7 cf 89 44 24 3c 66 89 6c 24 38 ff 15 a5 2e 02 00 8d 55 ff 44 8d 45 04 8b cd 66 89 44 24 3a ff 15 01 32 02 00 48 8b f8 48 83 f8 ff 75 20 48 8d 15 e1 c5 01 00 48 8b ce e8 81 30 00 00 48 0b df 48 ff c3 80 3c 1e 00 75 f7 e9 c9 00 00 00 48 8d 54 24 38 41 b8 10 00 00 00 48 8b c8 ff 15 f4 31 02 00 83 f8 ff 75 6b 48 8d 15 a8 c5 01 00 48 8b ce e8 48 30 00 00 48 83 cb }
		$seq4 = { 40 55 48 8d ac 24 e0 fb ff ff 48 81 ec 20 05 00 00 48 8b 05 b8 fc 01 00 48 33 c4 48 89 85 10 04 00 00 48 8d 8d f1 00 00 00 33 d2 41 b8 03 01 00 00 c6 85 f0 00 00 00 00 e8 93 59 00 00 48 8d 8d 01 02 00 00 33 d2 41 b8 07 02 00 00 c6 85 00 02 00 00 00 e8 78 59 00 00 48 8d 4d e1 33 d2 41 b8 03 01 00 00 c6 45 e0 00 e8 63 59 00 00 48 8d 95 f0 00 00 00 41 b8 f4 01 00 00 33 c9 ff 15 2e 30 02 00 85 c0 0f 84 5e 01 00 00 48 8d 55 e0 b9 f4 01 00 00 48 89 9c 24 30 05 00 00 48 89 bc 24 38 05 00 00 ff 15 17 30 02 00 4c 8d 05 20 15 02 00 48 8d 4d e0 ba 04 01 00 00 e8 5a 37 00 00 48 8d 45 e0 4c 8d 0d f7 14 02 00 48 89 44 24 28 48 8d 85 f0 00 00 00 4c 8d 85 f0 00 00 00 48 8d 15 dd c3 01 00 48 8d 8d 00 02 00 00 48 89 44 24 20 e8 fc 10 00 00 33 ff 48 8d 4d e0 48 89 7c 24 30 44 8d 47 03 45 33 c9 ba 00 00 00 40 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 ff 15 6f 2f 02 00 48 8b d8 }
		$seq5 = { 48 89 5c 24 10 48 89 74 24 18 48 89 7c 24 20 55 48 8d ac 24 70 f2 ff ff 48 81 ec 90 0e 00 00 48 8b 05 da ed 01 00 48 33 c4 48 89 85 80 0d 00 00 48 8b f1 48 8d 8d 81 05 00 00 33 d2 41 b8 ff 07 00 00 c6 85 80 05 00 00 00 e8 b2 4a 00 00 48 8d 4d 71 33 d2 41 b8 03 01 00 00 c6 45 70 00 e8 9d 4a 00 00 33 c0 c6 44 24 50 00 39 05 f4 1c 02 00 89 44 24 51 75 0b e8 b5 dd ff ff 89 05 e3 1c 02 00 48 8d 4d 70 e8 c6 e3 ff ff 8b 05 e8 b5 01 00 48 8d 8d 81 01 00 00 89 44 24 50 0f b6 05 da b5 01 00 33 d2 41 b8 ff 03 00 00 c6 85 80 01 00 00 00 88 44 24 54 e8 46 4a 00 00 48 8d 15 3f b6 01 00 48 8d 8d 80 01 00 00 e8 b3 1f 00 00 48 8d 4d 90 33 d2 0f 10 05 b6 b6 01 00 0f 10 0d bf b6 01 00 41 b8 d4 00 00 00 0f 29 44 24 60 0f 29 4c 24 70 0f 10 05 b8 b6 01 00 0f 29 45 80 e8 ff 49 00 00 48 83 cb ff 48 8b c3 0f 1f 84 }

	condition:
		uint16(0)==0x5a4d and filesize >60KB and 4 of ($seq*)
}