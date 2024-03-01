rule RUSSIANPANDA_Win_Mal_D3Fack_Loader
{
	meta:
		description = "Detects D3F@ck Loader"
		author = "RussianPanda"
		id = "54f6e5b0-0fcb-504b-bf1f-62cef9c912c0"
		date = "2024-02-25"
		modified = "2024-02-25"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1f0985c563eef9f1cda476556d29082a25bee0b3/D3F@ck_Loader/win_mal_D3F@ck_Loader.yar#L1-L12"
		license_url = "N/A"
		logic_hash = "3b277709c8a3ee445067a70881a5a0f67967c0a021aae198829f022d80ebef91"
		score = 75
		quality = 81
		tags = ""

	strings:
		$s1 = {64 61 74 61 2F [1-15] 2F [1-15] 2E}
		$s2 = {65 78 65 63 75 74 65 50 6F 77 65 72 53 68 65 6C 6C 43 6F 6D 6D 61 6E 64}
		$s3 = {64 6F 77 6E 6C 6F 61 64 41 6E 64 52 75 6E 46 69 6C 65}

	condition:
		all of them
}
