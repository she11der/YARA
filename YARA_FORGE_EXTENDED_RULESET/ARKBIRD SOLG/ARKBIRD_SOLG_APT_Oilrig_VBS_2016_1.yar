rule ARKBIRD_SOLG_APT_Oilrig_VBS_2016_1 : FILE
{
	meta:
		description = "Detect VBS script in base 64 used by OilRig (2016)"
		author = "Arkbird_SOLG"
		id = "5cc3a3f1-4f2f-56c4-af69-8652d22b6730"
		date = "2020-08-26"
		modified = "2021-07-13"
		reference = "https://twitter.com/Arkbird_SOLG/status/1298758788028264450"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-08-26/APT_OilRig_2016.yar#L4-L23"
		license_url = "N/A"
		logic_hash = "a6c42c46c80ca79b01aa0475c823aeccef416a0f8c2f58db95392cbe125b2fad"
		score = 75
		quality = 63
		tags = "FILE"
		hash1 = "1edbb818ea75919bb70bd2496e789e89d26c94cdf65ab61ebb5f1403d45d323c"
		hash2 = "1191d5c1dd7f6ac38b8d72bee37415b3ff1c28a8f907971443ac3a36906e8bf5"

	strings:
		$block1 = { 53 45 39 4e 52 54 30 69 4a 58 42 31 59 6d 78 70 59 79 56 63 54 47 6c 69 63 6d 46 79 61 57 56 7a 58 43 49 }
		$block2 = { 43 6c 4e 46 55 6c 5a 46 55 6a 30 69 61 48 52 30 }
		$block3 = { 56 34 4c 6d 46 7a 63 48 67 2f 63 6d 56 78 }
		$block4 = { 6a 30 69 63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 41 69 49 69 5a 37 4a 48 64 6a 50 53 68 75 5a 58 63 74 62 32 4a 71 5a 57 4e 30 49 46 4e 35 63 33 52 6c 62 53 35 4f 5a 58 51 75 56 32 56 69 51 32 78 70 5a 57 35 30 4b 54 73 6b 64 32 4d 75 56 58 4e 6c 52 47 56 6d 59 58 56 73 64 45 4e 79 5a 57 52 6c 62 6e 52 70 59 57 78 7a 50 53 52 30 63 6e 56 6c 4f 79 52 33 59 79 35 49 5a 57 46 6b 5a 58 4a 7a 4c 6d 46 6b 5a 43 67 6e 51 57 4e 6a 5a 58 42 30 4a 79 77 6e 4b 69 38 71 4a 79 6b 37 4a 48 64 6a 4c 6b 68 6c 59 57 52 6c 63 6e 4d 75 59 57 52 6b 4b 43 64 56 63 32 56 79 4c 55 46 6e 5a 57 35 30 4a 79 77 6e 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 49 45 4a 4a 56 46 4d 76 4e 79 34 33 4a 79 6b 37 64 32 68 70 62 47 55 6f 4d 53 6c 37 64 48 4a 35 65 79 52 79 50 55 64 6c 64 43 31 53 59 57 35 6b 62 32 30 37 4a 48 64 6a 4c 6b 52 76 64 32 35 73 62 32 46 6b 52 6d 6c 73 }
		$block5 = { 69 49 4e 43 6b 4e 79 5a 57 46 30 5a 55 39 69 61 6d 56 6a 64 43 67 69 56 31 4e 6a 63 6d 6c 77 64 43 35 54 61 47 56 73 62 43 49 70 4c 6c 4a 31 62 69 42 53 5a 58 42 73 59 57 [1-4] 45 52 33 62 69 77 69 4c 56 38 [1-4] 4a 6b 64 32 34 69 4b 53}
		$block6 = { 30 69 49 69 49 4e 43 6b 4e 79 5a 57 46 30 5a 55 39 69 61 6d 56 6a 64 43 67 69 56 31 4e 6a 63 6d 6c 77 64 43 35 54 61 47 56 73 62 43 49 70 4c 6c 4a 31 62 69 42 53 5a 58 42 73 59 57 4e 6c 4b 45 52 76 64 32 35 73 62 32 46 6b 52 58 68 6c 59 33 56 30 5a 53 77 69 4c 56 38 69 4c 43 4a 69 59 58 51 }
		$block7 = { 51 70 72 62 32 31 6a 50 53 4a 77 62 33 64 6c 63 6e 4e 6f 5a 57 78 73 49 43 31 6c 65 47 56 6a 49 45 4a 35 63 47 46 7a 63 79 41 74 52 6d 6c 73 5a 53 41 69 4a 6b }
		$block8 = { 0a b7 9a b5 e3 9b 8d e7 2d 59 27 2b 8a 9b 52 85 e9 65 46 e9 [1-4] d4 }

	condition:
		filesize <2KB and 6 of them
}