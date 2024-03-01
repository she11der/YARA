rule ARKBIRD_SOLG_APT_Turla_Ironpython_Apr_2021_1 : FILE
{
	meta:
		description = "Detect IronPython script used by Turla group"
		author = "Arkbird_SOLG"
		id = "303929d4-2c43-5e43-aeb0-09f469f7091b"
		date = "2021-04-30"
		modified = "2021-05-01"
		reference = "https://twitter.com/DrunkBinary/status/1388332507695919104"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2021-05-01/Turla/APT_Turla_IronPython_Apr_2021_1.yara#L1-L26"
		license_url = "N/A"
		logic_hash = "f6b626cddb4832f842a15eddce705fb24125e4341c425cf27dbbe537e2a98bdc"
		score = 75
		quality = 57
		tags = "FILE"
		hash1 = "65b43e30547ae4066229040c9056aa9243145b9ae5f3b9d0a01a5068ef9a0361"
		hash2 = "c430ebab4bf827303bc4ad95d40eecc7988bdc17cc139c8f88466bc536755d4e"
		hash3 = "f76257749792cc4e54f75d0e7a83e7a4429395c5dbc48078a8068575d7e9a98"
		tlp = "White"
		adversary = "Turla"

	strings:
		$s1 = { 6c 61 6d 62 64 61 20 73 2c 6b 3a 27 27 2e 6a 6f 69 6e 28 5b 63 68 72 28 28 6f 72 64 28 63 29 5e 6b 29 25 30 78 31 30 30 29 20 66 6f 72 20 63 20 69 6e 20 73 5d 29 }
		$s2 = { 66 72 6f 6d 20 53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 20 69 6d 70 6f 72 74 2a }
		$s3 = { 52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 28 4b 65 79 53 69 7a 65 3d 31 32 38 2c 42 6c 6f 63 6b 53 69 7a 65 3d 31 32 38 29 }
		$s4 = { 72 65 74 75 72 6e 20 53 79 73 74 65 6d 2e 41 72 72 61 79 5b 53 79 73 74 65 6d 2e 42 79 74 65 5d 28 5b 6f 72 64 28 78 29 66 6f 72 20 78 20 69 6e 20 6c 69 73 74 28 73 74 72 29 5d 29 }
		$s5 = { 53 79 73 74 65 6d 2e 41 72 72 61 79 2e 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 28 53 79 73 74 65 6d 2e 42 79 74 65 2c [10-12] 2e 4c 65 6e 67 74 68 29 }
		$s6 = { 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 [4-10] 5b 31 36 3a 5d 29 2c 73 79 73 2e 61 72 67 76 5b 31 5d 2c [4-10] 5b 3a 31 36 5d 2c }
		$s7 = { 41 73 73 65 6d 62 6c 79 2e 4c 6f 61 64 28 }
		$s8 = { 20 69 66 20 6c 65 6e 28 73 79 73 2e 61 72 67 76 29 21 3d 32 3a }
		$s9 = { 65 78 63 65 70 74 20 53 79 73 74 65 6d 2e 53 79 73 74 65 6d 45 78 63 65 70 74 69 6f 6e 20 61 73 20 65 78 3a }
		$s10 = { 69 66 20 5f 5f 6e 61 6d 65 5f 5f 3d 3d }
		$s11 = { 2e 66 6f 72 6d 61 74 28 65 78 2e 4d 65 73 73 61 67 65 2c 65 78 2e 53 74 61 63 6b 54 72 61 63 65 29 29 }

	condition:
		filesize >100KB and 9 of ($s*)
}
