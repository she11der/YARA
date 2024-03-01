rule ARKBIRD_SOLG_MAL_Heinote_June_2020_1 : FILE
{
	meta:
		description = "Detect Hienote malware"
		author = "Arkbird_SOLG"
		id = "5c0e604a-83d4-5c6f-83fa-0df878da80d8"
		date = "2020-06-26"
		modified = "2023-11-22"
		reference = "https://twitter.com/JAMESWT_MHT/status/1276471822217891840"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-06-26/Heinote_June_2020-1.yar#L1-L29"
		license_url = "N/A"
		logic_hash = "679f1113c9c770910d18da395b13aaef009ecdde91a0c11f931d0d7e63ed122a"
		score = 75
		quality = 61
		tags = "FILE"
		hash1 = "e0a34b9c420ddd930b3f89c13c3f564907dd948e88f668a0fe55ce506220bd73"

	strings:
		$s1 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 4c 4f 43 4b 5d 5b 53 45 54 5d 2d 2d 2d 2d }
		$s2 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 4c 4f 43 4b 5d 5b 47 45 54 5d 2d 2d 2d 2d }
		$s3 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 4c 4f 43 4b 5d 5b 47 45 54 5d 5b 53 48 48 65 6c 70 65 72 5d 20 47 65 74 4d 61 69 6e 50 61 67 65 20 6c 70 73 7a 75 72 6c 20 3d 20 25 73 }
		$s4 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 4c 4f 43 4b 5d 5b 53 45 54 5d 5b 53 48 48 65 6c 70 65 72 5d 20 73 74 61 74 75 73 20 3d 20 25 64 2f 25 64 20 67 65 74 20 3d 20 25 73 20 73 65 74 20 3d 20 25 73 }
		$s5 = { 44 65 62 75 67 49 6e 66 6f }
		$s6 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 46 41 56 5d 5b 53 45 54 5d 2d 2d 2d 2d }
		$s7 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 46 41 56 5d 5b 53 45 54 5d 5b 53 48 48 65 6c 70 65 72 5d 20 66 61 76 20 72 65 74 20 3d 20 25 64 0a }
		$s8 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 46 41 56 5d 5b 53 45 54 5d 5b 53 48 48 65 6c 70 65 72 5d 20 69 20 3d 20 25 64 20 6c 70 73 7a 4d 61 67 69 63 20 3d 20 25 73 0a }
		$s9 = { 5b 44 45 42 55 47 49 4e 46 4f 5d 5b 53 45 54 43 4f 4f 4b 49 45 48 41 4f 31 32 33 5d 20 6f 6b 20 6f 6b 0a }
		$s10 = { 75 73 65 72 6e 61 6d 65 3d 22 25 73 22 2c 20 72 65 61 6c 6d 3d 22 25 73 22 2c 20 6e 6f 6e 63 65 3d 22 25 73 22 2c 20 75 72 69 3d 22 25 73 22 2c 20 63 6e 6f 6e 63 65 3d 22 25 73 22 2c 20 6e 63 3d 25 30 38 78 2c 20 71 6f 70 3d 25 73 2c 20 72 65 73 70 6f 6e 73 65 3d 22 25 73 22 }
		$s11 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" fullword ascii
		$s12 = { 25 73 20 63 6f 6f 6b 69 65 20 25 73 3d 22 25 73 22 20 66 6f 72 20 64 6f 6d 61 69 6e 20 25 73 2c 20 70 61 74 68 20 25 73 2c 20 65 78 70 69 72 65 20 25 49 36 34 64 0a }
		$s13 = "User-Agent: %s" fullword ascii
		$s14 = "Send failure: %s" fullword ascii
		$s15 = "ftp://%s:%s@%s" fullword ascii
		$s16 = "Host: %s%s%s" fullword ascii
		$s17 = "Referer: %s" fullword ascii

	condition:
		uint16(0)==0x4D5A and filesize <450KB and 14 of them
}
