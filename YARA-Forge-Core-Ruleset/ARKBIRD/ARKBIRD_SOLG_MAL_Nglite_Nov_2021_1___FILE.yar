rule ARKBIRD_SOLG_MAL_Nglite_Nov_2021_1___FILE
{
	meta:
		description = "Detect NGLite backdoor (version A)"
		author = "Arkbird_SOLG"
		id = "cf2845f3-1176-5197-9d05-f123b0f23c75"
		date = "2021-11-09"
		modified = "2021-11-09"
		reference = "https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-11-08/NGLite/MAL_NGLite_Nov_2021_1.yara#L1-L19"
		license_url = "N/A"
		logic_hash = "ebafc52da76b9a960ee3c2c99955fb5dcb4acff2b7a0d7fad714bfc17617331a"
		score = 75
		quality = 75
		tags = "FILE"
		hash1 = "7e4038e18b5104683d2a33650d8c02a6a89badf30ca9174576bf0aff08c03e72"
		hash2 = "3da8d1bfb8192f43cf5d9247035aa4445381d2d26bed981662e3db34824c71fd"
		tlp = "white"
		adversary = "-"

	strings:
		$s1 = { 48 8b 05 48 e7 90 00 48 8d 0d 99 4b 99 00 48 89 04 24 48 89 4c 24 08 48 c7 44 24 10 08 02 00 00 e8 82 21 00 00 48 8b 44 24 18 48 85 c0 74 33 48 3d 08 02 00 00 77 2b 48 8d 1d 69 4b 99 00 c6 04 03 5c 48 ff c0 48 89 05 4b 3f 99 00 e9 d6 fe ff ff 31 c0 e8 8f fc 02 00 ba 09 02 00 00 e8 b5 fc 02 00 48 8d 05 fe d5 55 00 48 89 04 24 48 c7 44 24 08 24 00 00 00 e8 cc 44 00 00 31 c0 e8 65 fc 02 00 90 e8 af d2 02 }
		$s2 = { 48 83 ec 70 48 89 6c 24 68 48 8d 6c 24 68 48 c7 44 24 30 00 00 00 00 48 c7 44 24 28 00 00 00 00 48 8b 05 bf dc 90 00 48 89 04 24 48 c7 44 24 08 ff ff ff ff 48 8d 44 24 30 48 89 44 24 10 48 8d 44 24 28 48 89 44 24 18 e8 39 17 00 00 48 83 7c 24 20 00 74 35 31 c0 31 c9 eb 24 48 89 ca 48 89 c1 bb 01 00 00 00 48 d3 e3 48 23 5c 24 30 48 8d 72 01 48 85 db 48 0f 45 d6 48 ff c0 48 89 d1 48 83 f8 40 7c d6 48 85 c9 75 3e 0f 57 c0 0f 11 44 24 38 0f 11 44 24 48 0f 11 44 24 58 48 8b 05 23 dc 90 00 48 89 04 24 48 8d 44 24 38 48 89 44 24 08 e8 10 16 00 00 8b 44 24 58 89 44 24 78 48 8b 6c 24 68 48 83 c4 70 c3 89 4c 24 78 48 8b 6c 24 68 48 }
		$s3 = { 48 8b 05 60 cc 90 00 48 89 04 24 0f 57 c0 0f 11 44 24 08 0f 11 44 24 18 e8 02 07 00 00 48 8b 44 24 28 48 8b 4c 24 40 48 89 81 10 03 00 00 48 85 c0 0f 84 80 00 00 00 48 8b 05 29 cc 90 00 48 89 04 24 0f 57 c0 0f 11 44 24 08 0f 11 44 24 18 e8 cb 06 00 00 48 8b 44 24 28 48 8b 4c 24 40 48 89 81 18 03 00 00 48 85 c0 74 0a 48 8b 6c 24 30 48 83 c4 38 c3 48 8d 05 ac e0 56 00 48 89 04 24 e8 1b b6 02 00 48 8b 05 e4 cb 90 00 48 8b 4c 24 40 48 8b 91 10 03 00 00 48 89 04 24 48 89 54 24 08 e8 5a 05 00 00 48 8b 44 24 40 48 c7 80 10 03 00 00 00 00 00 00 eb b3 48 8d 05 61 e0 56 00 48 89 04 24 e8 d8 b5 02 00 e9 6b ff ff ff 48 8b 6c 24 30 48 83 c4 38 }
		$s4 = { 48 81 ec a0 00 00 00 48 89 ac 24 98 00 00 00 48 8d ac 24 98 00 00 00 48 c7 44 24 48 00 00 00 00 48 8b 05 8a c9 90 00 48 89 04 24 48 c7 44 24 08 ff ff ff ff 48 c7 44 24 10 fe ff ff ff 48 c7 44 24 18 ff ff ff ff 48 8d 44 24 48 48 89 44 24 20 0f 57 c0 0f 11 44 24 28 48 c7 44 24 38 02 00 00 00 e8 3b 05 00 00 65 48 8b 04 25 28 00 00 00 48 8b 80 00 00 00 00 48 8b 40 30 48 8b 4c 24 48 48 87 88 78 02 00 00 0f 57 c0 0f 11 44 24 68 0f 11 44 24 78 0f 11 84 24 88 00 00 00 48 8b 05 5f c8 90 00 48 89 04 24 48 8d 44 24 68 48 89 44 24 08 48 8d 44 24 68 48 89 44 24 10 48 c7 44 24 18 30 00 00 00 e8 59 03 00 00 48 83 7c 24 20 }
		$s5 = { 48 8b 15 26 29 92 00 48 89 14 24 48 89 4c 24 08 48 89 44 24 10 48 c7 44 24 18 00 10 00 00 48 c7 44 24 20 04 00 00 00 e8 71 64 01 00 48 83 7c 24 28 00 40 0f 94 c6 48 8b 44 24 38 48 8b 4c 24 48 48 8b 54 24 68 48 8b 5c 24 40 e9 61 ff ff ff 48 8b 6c 24 50 48 83 c4 58 c3 48 8b 6c 24 50 48 83 c4 58 c3 e8 25 91 01 00 48 8d 05 e2 b8 56 00 48 89 04 24 48 c7 44 24 08 19 00 00 00 e8 bc 9a 01 00 48 8b 44 24 38 48 89 04 24 e8 be 97 01 00 48 8d 05 9a b1 56 00 48 89 04 24 48 c7 44 24 08 19 00 00 00 e8 95 9a 01 00 8b 44 24 34 48 89 04 24 e8 98 97 01 00 e8 73 93 01 00 e8 5e 91 01 00 48 8d }

	condition:
		uint16(0)==0x5a4d and filesize >40KB and 4 of ($s*)
}