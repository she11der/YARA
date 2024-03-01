rule ARKBIRD_SOLG_RAN_ELK_Darkradiation_Jul_2021_2 : FILE
{
	meta:
		description = "Detect the DarkRadiation ransomware"
		author = "Arkbird_SOLG"
		id = "3580a41a-ba2e-5a47-b35d-b2482fbc913a"
		date = "2021-07-03"
		modified = "2021-07-05"
		reference = "https://bazaar.abuse.ch/browse/tag/DarkRadiation/"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-04/DarkRadiation/RAN_ELK_DarkRadiation_Jul_2021_2.yara#L1-L27"
		license_url = "N/A"
		logic_hash = "b21db1658845cafe37950d69b5bc0aab203e7bea3e43f95394236e0133234e2d"
		score = 75
		quality = 57
		tags = "FILE"
		hash1 = "3bab2947305c00df66cb4d6aaef006f10aca348c17aa2fd28e53363a08b7ec68"
		hash2 = "652ee7b470c393c1de1dfdcd8cb834ff0dd23c93646739f1f475f71a6c138edd"
		hash3 = "79aee7a4459d49dc6dfebf1a45d32ccc3769a1e5c1f231777ced3769607ba9c1"
		tlp = "White"
		adversary = "FERRUM"

	strings:
		$s1 = { 61 6c 6c 54 68 72 65 61 64 73 3d 28 24 31 29 }
		$s2 = { 4d 53 47 5f 55 52 4c 3d 27 68 74 74 70 73 3a 2f 2f 61 70 69 2e 74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 27 24 54 4f 4b 45 4e 27 2f 73 65 6e 64 4d 65 73 73 61 67 65 3f 63 68 61 74 5f 69 64 3d 27 }
		$s3 = { 69 66 20 5b 5b 20 22 24 6d 61 73 74 65 72 22 20 21 3d 20 22 24 73 6c 61 76 65 22 20 5d 5d }
		$s4 = { 75 73 65 72 5f 68 6f 73 74 3d 24 28 65 63 68 6f 20 22 24 7b 70 61 72 73 65 5f 61 72 67 7d 22 20 7c 20 61 77 6b 20 2d 46 20 22 7c 22 20 27 7b 70 72 69 6e 74 20 24 31 7d 27 29 }
		$s5 = { 6d 61 73 74 65 72 3d 24 28 63 61 74 20 2f 74 6d 70 2f 2e 63 63 77 20 7c 20 77 63 20 2d 6c 29 }
		$s6 = { 73 65 6e 64 5f 6d 65 73 73 61 67 65 20 24 69 64 20 22 24 28 68 6f 73 74 6e 61 6d 65 29 20 24 28 68 6f 73 74 6e 61 6d 65 20 2d 49 29 }
		$s7 = { 73 74 61 72 74 5f 74 68 72 65 61 64 20 24 61 6c 6c 54 68 72 65 61 64 73 }
		$s8 = { 69 70 5f 68 6f 73 74 3d 24 28 65 63 68 6f 20 22 24 7b 70 61 72 73 65 5f 61 72 67 7d 22 20 7c 20 61 77 6b 20 2d 46 20 22 7c 22 20 27 7b 70 72 69 6e 74 20 24 32 7d 27 29 }
		$s9 = { 70 6f 72 74 5f 68 6f 73 74 3d 24 28 65 63 68 6f 20 22 24 7b 70 61 72 73 65 5f 61 72 67 7d 22 20 7c 20 61 77 6b 20 2d 46 20 22 7c 22 20 27 7b 70 72 69 6e 74 20 24 33 7d 27 29 }
		$s10 = { 24 28 63 75 72 6c 20 2d 73 20 2d 2d 69 6e 73 65 63 75 72 65 20 2d 2d 64 61 74 61 2d 75 72 6c 65 6e 63 6f 64 65 20 22 74 65 78 74 3d [2-15] 22 20 22 24 4d 53 47 5f 55 52 4c [2-15] 22 20 26 29 }
		$s11 = { 73 6c 61 76 65 3d 24 28 65 63 68 6f 20 22 24 7b [2-15] 7d 22 20 7c 20 77 63 20 2d 6c 29 }

	condition:
		filesize >1KB and 6 of ($s*)
}
