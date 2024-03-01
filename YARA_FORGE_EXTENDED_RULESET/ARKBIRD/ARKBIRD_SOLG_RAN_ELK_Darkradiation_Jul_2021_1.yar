rule ARKBIRD_SOLG_RAN_ELK_Darkradiation_Jul_2021_1 : FILE
{
	meta:
		description = "Detect the DarkRadiation ransomware"
		author = "Arkbird_SOLG"
		id = "13d77ecc-14ab-54ce-9eec-2d614f5ae8e4"
		date = "2021-07-03"
		modified = "2021-07-05"
		reference = "https://bazaar.abuse.ch/browse/tag/DarkRadiation/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-04/DarkRadiation/RAN_ELK_DarkRadiation_Jul_2021_1.yara#L1-L25"
		license_url = "N/A"
		logic_hash = "6fbc6eed7dd7f92af0cd8b3b2726636a64dc8de0b795b176169817994f44d4fa"
		score = 75
		quality = 61
		tags = "FILE"
		hash1 = "1c2b09417c1a34bbbcb8366c2c184cf31353acda0180c92f99828554abf65823"
		hash2 = "d0d3743384e400568587d1bd4b768f7555cc13ad163f5b0c3ed66fdc2d29b810"
		hash3 = "e380c4b48cec730db1e32cc6a5bea752549bf0b1fb5e7d4a20776ef4f39a8842"
		tlp = "White"
		adversary = "FERRUM"

	strings:
		$s1 = { 50 41 53 53 5f 44 45 43 3d 24 28 6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 62 61 73 65 36 34 20 2d 61 65 73 2d 32 35 36 2d 63 62 63 20 2d 64 20 2d 70 61 73 73 20 70 61 73 73 3a 24 50 41 53 53 5f 44 45 20 3c 3c 3c 20 24 31 29 }
		$s2 = { 72 6d 20 2d 72 66 20 24 50 41 54 48 5f 54 45 4d 50 5f 46 49 4c 45 2f 24 4e 41 4d 45 5f 53 43 52 49 50 54 5f 43 52 59 50 54 }
		$s3 = { 74 65 6c 65 67 72 61 6d 5f 62 6f 74 2f [5-15] 2d 6f 20 22 2f }
		$s4 = { 2d 6f 20 22 2f 74 6d 70 2f 62 61 73 68 2e 73 68 22 3b 63 64 20 2f 74 6d 70 3b 63 68 6d 6f 64 20 2b 78 20 62 61 73 68 2e 73 68 3b 2e 2f 62 61 73 68 2e 73 68 3b }
		$s5 = { 78 61 72 67 73 20 2d 50 20 31 30 20 2d 49 20 46 49 4c 45 20 6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 61 65 73 2d 32 35 36 2d 63 62 63 20 2d 73 61 6c 74 20 2d 70 61 73 73 20 70 61 73 73 }
		$s6 = { 78 61 72 67 73 20 2d 50 20 31 30 20 2d 49 20 46 49 4c 45 20 6f 70 65 6e 73 73 6c 20 65 6e 63 20 2d 61 65 73 2d 32 35 36 2d 63 62 63 20 2d 73 61 6c 74 20 2d 70 61 73 73 20 70 61 73 73 3a 24 50 41 53 53 5f 44 45 43 20 2d 69 6e 20 46 49 4c 45 20 2d 6f 75 74 20 46 49 4c 45 2e }
		$s7 = { 75 73 65 72 6d 6f 64 20 2d 2d 73 68 65 6c 6c 20 2f 62 69 6e 2f 6e 6f 6c 6f 67 69 6e }
		$s8 = { 67 72 65 70 20 2d 46 20 22 24 22 20 2f 65 74 63 2f 73 68 61 64 6f 77 20 7c 20 63 75 74 20 2d 64 3a 20 2d 66 31 20 7c 20 67 72 65 70 20 2d 76 20 22 [1-15] 22 20 7c 20 78 61 72 67 73 20 2d 49 20 46 49 4c 45 20 67 70 61 73 73 77 64 20 2d 64 20 46 49 4c 45 20 77 68 65 65 6c }
		$s9 = { 73 79 73 74 65 6d 63 74 6c 20 73 74 6f 70 20 64 6f 63 6b 65 72 20 26 26 20 73 79 73 74 65 6d 63 74 6c 20 64 69 73 61 62 6c 65 20 64 6f 63 6b 65 72 }

	condition:
		filesize >5KB and 5 of ($s*)
}
