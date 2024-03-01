rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_DECAF
{
	meta:
		description = "Detects files referencing identities associated with DECAF ransomware"
		author = "ditekShen"
		id = "24422015-56f3-503e-a902-0183eb601b22"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L376-L408"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8fca3a6564cd11e625b65e7f0f278b79678368dd0c77440e9f8d46035e0c3426"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "22eb687475f2c5ca30b@protonmail.com" ascii wide nocase
		$s2 = { 4d 49 49 42 43 67 4b 43 41 51 45 41 71 34 6b 31
                48 64 62 31 54 48 72 7a 42 42 65 4f 31 38 34 6b
                6e 43 62 42 4b 72 30 33 61 70 66 58 71 6c 4f 6b
                53 64 74 48 53 4a 67 66 79 49 71 4a 50 47 78 6c
                0a 2f 63 46 69 73 4a 6d 56 58 52 33 2f 74 34 65
                39 46 62 4c 73 45 49 75 54 70 39 50 4a 54 63 69
                6f 6d 48 66 72 35 43 67 43 51 7a 68 6e 41 5a 30
                41 76 6a 47 42 61 57 50 36 4b 70 43 79 66 44 6e
                73 0a 79 62 72 75 79 4b 71 79 67 61 57 70 5a 53
                41 6e 7a 52 64 42 2b 54 41 6b 75 35 69 71 79 38
                71 31 56 77 6e 4e 35 37 51 42 6c 74 72 6f 30 59
                4a 5a 38 65 6e 4b 5a 52 54 6c 63 7a 6d 74 6a 65
                4f 70 0a 42 2f 78 75 54 4f 75 44 6a 6d 55 53 4e
                69 47 79 69 6a 57 42 56 66 59 6b 37 73 56 58 6c
                2f 6c 51 38 74 61 58 72 33 36 78 50 57 68 4d 49
                47 30 45 71 52 56 72 46 56 2b 63 61 76 53 37 5a
                34 76 61 0a 79 58 6d 63 66 35 35 4e 6b 70 4d 47
                4b 4b 59 38 75 71 76 77 62 34 61 4c 49 4b 61 62
                65 6b 32 6e 55 57 42 67 4e 67 53 4f 74 71 42 4c
                4c 4c 32 41 32 62 59 2f 35 73 30 47 4a 2f 56 56
                2b 45 6d 49 0a 58 37 2f 7a 49 2b 46 63 65 55 2b
                64 63 4e 58 2f 69 72 30 75 6a 50 34 79 73 34 6d
                2f 6a 6a 5a 44 34 77 49 44 41 51 41 42 }

	condition:
		any of them
}
