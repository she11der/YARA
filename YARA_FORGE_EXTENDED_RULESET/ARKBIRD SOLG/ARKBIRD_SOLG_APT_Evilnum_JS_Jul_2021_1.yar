rule ARKBIRD_SOLG_APT_Evilnum_JS_Jul_2021_1 : FILE
{
	meta:
		description = "Detect JS script used by EvilNum group"
		author = "Arkbird_SOLG"
		id = "08b410c4-4899-5280-9735-6b3017c7a813"
		date = "2020-07-13"
		modified = "2021-07-14"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-07-13/EvilNum/APT_EvilNum_JS_Jul_2021_1.yara#L1-L22"
		license_url = "N/A"
		logic_hash = "0ace40e54f6dca078f17e7e157c7973642b83366ba792d2bcdc0d971f729fb68"
		score = 75
		quality = 69
		tags = "FILE"
		hash1 = "8420577149bef1eb12387be3ea7c33f70272e457891dfe08fdb015ba7cd92c72"
		hash2 = "c16824a585c9a77332fc16357b5e00fc110c00535480e9495c627f656bb60f24"
		hash3 = "1061baf604aaa7ed5ba3026b9367de7b6c7f20e7e706d9e9b5308c45a64b2679"
		tlp = "white"
		adversary = "EvilNum"

	strings:
		$s1 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 42 61 73 65 36 34 44 61 74 61 22 29 3b }
		$s2 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 6d 6c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 22 29 2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 42 61 73 65 36 34 44 61 74 61 22 29 3b }
		$s3 = { 69 66 20 28 2d 31 20 21 3d 20 57 53 63 72 69 70 74 2e 53 63 72 69 70 74 46 75 6c 6c 4e 61 6d 65 2e 69 6e 64 65 78 4f 66 28 [1-8] 28 22 }
		$s4 = { 52 75 6e 28 [1-8] 30 2c 20 30 29 }
		$s5 = { 7d 2c 20 ?? 20 3d 20 ?? 2e 63 68 61 72 43 6f 64 65 41 74 28 30 29 2c 20 ?? 20 3d 20 ?? 2e 73 6c 69 63 65 28 31 2c 20 31 20 2b 20 ?? 29 2c 20 ?? 20 3d 20 ?? 2e 73 6c 69 63 65 28 31 20 2b 20 ?? 20 2b 20 34 29 2c 20 ?? 20 3d 20 5b 5d 2c }
		$s6 = { 57 53 63 72 69 70 74 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 3b }
		$s7 = { 5b ?? 5d 20 3d 20 ?? 20 2b 20 22 2d 22 20 2b 20 ?? 20 2b 20 22 2d 22 20 2b 20 ?? 20 2b 20 22 54 22 20 2b 20 ?? 20 2b 20 22 3a 22 20 2b 20 ?? 20 2b 20 22 3a 22 20 2b 20 ?? 3b }

	condition:
		filesize >8KB and 6 of ($s*)
}
