rule ARKBIRD_SOLG_Mal_Xcaon_Jul_2021_1 : FILE
{
	meta:
		description = "Detect the xCaon malware"
		author = "Arkbird_SOLG"
		id = "bcd5a52d-9547-5709-95f4-9d1f956f623c"
		date = "2021-07-01"
		modified = "2021-07-02"
		reference = "https://research.checkpoint.com/2021/indigozebra-apt-continues-to-attack-central-asia-with-evolving-tools/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-02/IndigoZebra/Mal_xCaon_Jul_2021_1.yara#L1-L21"
		license_url = "N/A"
		logic_hash = "9c3e3d0035596323a505404ecc067bd2b87a4b0ac7499f1c87aac015f59eb65a"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "8be3b10406f690ae5cf46c1dba18cb9a1c75bf646defcc9cab81d40fe0e0cc1b"
		hash2 = "e9013f35ce11fc4c5eb2c21827bdc459202d362365d6ea5b724dee4fe0088bd1"
		hash3 = "489fca69a622195328302e64e29b6183feac90826dce198432d603202ca4d216"
		tlp = "White"
		adversary = "IndigoZebra"

	strings:
		$s1 = { a1 7c 10 41 00 33 c5 89 45 fc 8b 45 08 56 57 6a 49 89 85 f8 80 ff ff 58 6a 50 66 89 45 c8 58 6a 48 66 89 45 ca 58 6a 4c 66 89 45 cc 58 6a 50 66 89 45 ce 58 6a 41 66 89 45 d0 58 6a 50 66 89 45 d2 58 6a 49 66 89 45 d4 58 6a 2e 66 89 45 d6 58 6a 44 66 89 45 d8 58 66 89 45 da 6a 4c 58 66 89 45 dc 66 89 45 de 33 c0 66 89 45 e0 8d 45 c8 50 c7 45 e4 47 65 74 41 c7 45 e8 64 61 70 74 c7 45 ec 65 72 73 49 c7 45 f0 6e 66 6f 00 ff 15 50 d0 40 00 8d 4d e4 51 50 89 85 f4 80 ff ff ff 15 54 d0 40 00 8d 8d f0 80 ff ff 51 8d 8d fc 80 ff ff 51 c7 85 f0 80 ff ff 90 7e 00 00 ff d0 8b c8 33 c0 c6 45 f4 00 8d 7d f5 ab 66 ab aa 85 c9 0f 85 1d 01 00 00 53 6a 25 5e 6a 30 5a 6a 32 59 8b c6 66 89 45 8c 8b c2 66 89 45 8e 6a 58 8b c1 66 89 45 90 58 8b f8 6a 2d 66 89 7d 92 5f 8b df 66 89 5d 94 8b de 66 89 5d 96 8b da 66 89 5d 98 8b d9 66 89 5d 9a 8b d8 66 89 5d 9c 8b df 66 89 5d 9e 8b de 66 89 5d a0 8b da 66 89 5d a2 8b d9 66 89 5d a4 8b d8 66 89 5d a6 8b df 66 89 5d a8 8b de 66 89 5d aa 8b da 66 89 5d ac 8b d9 66 89 5d ae 8b d8 66 89 5d b0 8b df 66 89 5d b2 8b de 66 89 5d b4 8b da 66 89 5d b6 8b d9 66 89 45 c4 66 89 5d b8 8b d8 33 c0 66 89 45 c6 6a 06 8d 85 90 82 ff ff 50 8d 45 f4 50 66 89 5d ba 66 89 7d bc 66 89 75 be 66 89 55 c0 66 89 4d c2 e8 ?? 17 00 00 0f b6 45 f9 50 0f b6 45 f8 50 0f b6 45 f7 50 0f b6 45 f6 50 0f b6 45 f5 50 0f b6 45 f4 50 8d 45 8c 50 ff b5 f8 80 ff ff ff 15 44 d1 40 00 83 c4 2c 33 f6 46 5b ff b5 f4 80 ff ff ff 15 4c d0 40 00 8b }
		$s2 = { 6a 5b 58 6a 55 66 89 45 c4 58 6a 70 66 89 45 c6 58 6a 6c 66 89 45 c8 58 6a 6f 66 89 45 ca 58 6a 61 66 89 45 cc 58 6a 64 66 89 45 ce 58 6a 5d 66 89 45 d0 58 6a 0d 66 89 45 d2 58 6a 0a 66 89 45 d4 58 6a 25 66 89 45 d6 33 c0 66 89 45 d8 58 6a 74 66 89 45 ac 8b c6 66 89 45 ae 58 6a 6d 66 89 45 b0 58 6a 70 66 89 45 b2 58 6a 25 66 89 45 b4 58 6a 64 66 89 45 b6 58 6a 2e 66 89 45 b8 58 6a 6c 66 89 45 ba 58 6a 6f 66 89 45 bc 58 6a 67 66 89 45 be 58 6a 46 66 89 45 c0 33 c0 66 89 45 c2 58 6a 69 66 89 45 dc 58 6a 6c 66 89 45 de 58 6a 65 66 89 45 e0 58 6a 3a 66 89 45 e2 58 66 89 45 e4 6a 25 58 66 89 45 e6 6a 0d 58 66 89 45 ea 6a 0a 58 66 89 45 ec 33 c0 66 89 45 ee 8d 45 c4 50 66 89 75 e8 e8 ?? 11 00 00 59 8d 4d c4 8d b5 50 f3 ff ff e8 [2] ff ff 89 bd 4c f2 ff ff c7 85 48 f3 ff ff 0f 00 00 00 89 bd 44 f3 ff ff c6 85 34 f3 ff ff 00 8d 85 34 f3 ff ff 50 83 ec 1c c6 45 fc 03 8d 85 fc f2 ff ff 8b f4 89 a5 50 f2 ff ff 50 e8 [2] ff ff e8 [2] ff ff 8b 9d 34 f3 ff ff 83 c4 20 83 bd 48 f3 ff ff 10 73 06 8d 9d 34 f3 ff ff 8d 85 4c f2 ff ff 50 }
		$s3 = { 83 c4 10 8d 85 6c fb ff ff 50 68 04 01 00 00 ff 15 2c d0 40 00 33 c0 56 66 89 85 74 fd ff ff 8d 85 76 fd ff ff 53 50 e8 ?? 10 00 00 83 c4 0c ff 15 30 d0 40 00 8b 35 44 d1 40 00 50 8d 85 6c fb ff ff 50 8d 45 ac 50 8d 85 74 fd ff ff 50 ff d6 83 c4 10 53 68 80 00 00 00 6a 02 53 53 68 00 00 00 40 8d 85 74 fd ff ff 50 ff 15 24 d0 40 00 8b f8 83 ff ff 74 79 53 8d 85 50 f2 ff ff 50 ff b5 4c f2 ff ff 89 9d 50 f2 ff ff ff b5 48 f2 ff ff 57 ff 15 14 d0 40 00 57 ff 15 34 d0 40 00 33 c0 68 fe 07 00 00 66 89 85 6c f3 ff ff 8d 85 6e f3 ff ff 53 50 e8 ?? 10 00 00 8d 85 74 fd ff ff 50 8d 45 dc 50 8d 85 6c f3 ff ff 50 ff d6 8d 85 6c f3 ff ff 50 8d 85 18 f3 ff ff 50 8d 8d 50 f3 ff ff e8 [2] ff ff 83 }
		$s4 = { 8b 45 08 33 ff 89 85 60 f1 ff ff 89 bd 5c f1 ff ff 33 c0 be 06 02 00 00 89 7d fc 56 66 89 85 88 fb ff ff 8d 85 8a fb ff ff 57 50 e8 [2] 00 00 33 c0 56 66 89 85 80 f9 ff ff 8d 85 82 f9 ff ff 57 50 e8 [2] 00 00 83 c4 18 6a 43 58 6a 6f 66 89 45 e0 58 6a 6d 66 89 45 e2 58 6a 53 66 89 45 e4 58 6a 70 66 89 45 e6 58 6a 65 66 89 45 e8 58 6a 63 66 89 45 ea 58 66 89 45 ec 33 c0 66 89 45 ee bb 04 01 00 00 53 8d 85 88 fb ff ff 50 8d 45 e0 50 ff 15 00 d0 40 00 8d 85 80 f9 ff ff 50 53 ff 15 2c d0 40 00 6a 25 58 6a 73 5b 6a 63 66 89 45 c0 8b c3 66 89 45 c2 58 6a 63 66 89 45 c4 8b c3 66 89 45 c6 58 6a 6f 66 89 45 c8 58 6a 64 66 89 45 ca 58 6a 65 66 89 45 cc 58 66 89 45 ce 6a 25 58 6a 64 66 89 45 d0 58 6a 2e 66 89 45 d2 58 6a 6c 66 89 45 d4 58 6a 6f 66 89 45 d6 58 6a 67 66 89 45 d8 58 66 89 45 da 33 c0 68 fe 07 00 00 66 89 45 dc 66 89 85 80 f1 ff ff 8d 85 82 f1 ff ff 57 50 e8 [2] 00 00 33 c0 56 66 89 85 90 fd ff ff 8d 85 92 fd ff ff 57 50 e8 [2] 00 00 83 c4 18 6a 25 58 6a 20 66 89 45 98 8b c3 66 89 45 9a 58 6a 2f 8b c8 66 89 4d 9c 59 6a 41 66 89 4d 9e 59 6a 2f 66 89 4d a0 8b c8 66 89 4d a2 59 6a 43 66 89 4d a4 59 66 89 4d a6 6a 22 8b c8 66 89 4d a8 59 6a 25 66 89 4d aa 59 66 89 4d ac 6a 22 8b cb 66 89 4d ae 59 66 89 4d b0 8b c8 6a 3e 66 89 4d b2 59 66 89 45 b6 6a 25 58 66 89 45 b8 33 c0 66 89 4d b4 66 89 5d ba 66 89 45 bc ff 15 30 d0 40 00 8b 35 44 d1 40 00 50 8d 85 80 f9 ff ff 50 8d 45 c0 50 8d 85 90 fd ff ff 50 ff d6 8b 45 0c 83 c4 10 83 7d 20 08 73 03 8d 45 0c 8d 8d 90 fd ff ff 51 50 8d 85 88 fb ff ff 50 8d 45 98 50 8d 85 80 f1 ff ff 50 ff d6 6a 44 5e 56 8d 85 04 f1 ff ff 57 50 e8 [2] 00 00 6a 10 8d 85 48 f1 ff ff 57 50 89 b5 04 f1 ff ff e8 [2] 00 00 83 c4 2c 8d 85 04 f1 ff ff 50 ff 15 28 d0 40 00 33 c0 66 89 85 34 f1 ff ff 8d 85 48 f1 ff ff 50 8d 85 04 f1 ff ff 50 57 57 6a 10 57 57 57 8d 85 80 f1 ff ff 33 db 50 43 57 89 9d 30 f1 ff ff ff 15 08 d0 40 00 68 3f 77 1b 00 ff b5 48 f1 ff ff 8b f0 ff 15 0c d0 40 00 3b f7 0f 84 1c 01 00 00 ff b5 4c f1 ff ff 8b 35 34 d0 40 00 ff d6 ff b5 48 f1 ff ff ff d6 33 c0 c7 85 78 f1 ff ff 07 00 00 00 89 bd 74 f1 ff ff 66 89 85 64 f1 ff ff 57 57 6a 03 57 57 68 00 00 00 80 8d 85 90 fd ff ff 50 88 5d fc ff 15 24 d0 40 00 89 85 5c f1 ff ff 83 f8 ff 0f 84 96 00 00 00 57 50 ff 15 04 d0 40 00 89 85 58 f1 ff ff 83 f8 ff 75 2b ff b5 5c f1 ff ff ff d6 8b 85 60 f1 ff ff 68 64 f1 40 00 e8 f1 00 00 00 53 33 ff 8d b5 64 f1 ff ff e8 64 03 00 00 e9 95 00 00 00 83 c0 02 50 e8 [2] 00 00 8b d8 8b 85 58 f1 ff ff 83 c0 02 50 57 53 e8 [2] 00 00 83 c4 10 57 8d 85 58 f1 ff ff 50 ff b5 58 f1 ff ff 53 ff b5 5c f1 ff ff ff 15 20 d0 40 00 ff b5 5c f1 ff ff ff d6 8d 85 64 f1 ff ff 50 53 e8 d9 11 00 00 53 e8 [2] 00 00 83 c4 0c 8d 85 90 fd ff ff 50 ff 15 38 d0 40 00 8b b5 60 f1 ff ff 8d 9d 64 f1 ff ff e8 96 00 00 00 6a 01 33 ff 8b }
		$s5 = { be 06 02 00 00 89 ?? fc 56 66 89 85 ?? fb ff ff 8d 85 ?? fb ff ff ?? 50 e8 [2] 00 00 33 c0 56 66 89 85 ?? f9 ff ff 8d 85 ?? f9 ff ff ?? 50 e8 [2] 00 00 83 c4 18 6a 43 58 6a 6f 66 89 45 e0 58 6a 6d 66 89 45 e2 58 6a 53 66 89 45 e4 58 6a 70 66 89 45 e6 58 6a 65 66 89 45 e8 58 6a 63 66 89 45 ea 58 66 89 45 ec 33 c0 66 89 45 ee ?? 04 01 00 00 ?? 8d 85 ?? fb ff ff 50 8d 45 e0 50 ff 15 00 [2] 00 8d 85 ?? f9 ff ff 50 ?? ff 15 [3] 00 }
		$s6 = { 8b 45 08 [5] ff [5] 6a 07 89 85 10 ff ff ff ?? 33 ?? 33 c0 89 ?? 14 89 ?? 10 89 ?? 18 ff ff ff 66 89 ?? 8d ?? 1c 89 ?? fc 89 ?? 14 89 ?? 10 66 89 ?? 8d ?? 38 89 ?? 14 89 ?? 10 89 ?? 0c ff ff ff 66 89 ?? 89 ?? 6c 89 ?? 68 66 89 ?? 58 89 ?? 88 00 00 00 89 ?? 84 00 00 00 66 89 ?? 74 89 ?? b8 00 00 00 89 ?? b4 00 00 00 66 89 ?? a4 00 00 00 6a 68 }

	condition:
		uint16(0)==0x5a4d and filesize >30KB and 5 of ($s*)
}