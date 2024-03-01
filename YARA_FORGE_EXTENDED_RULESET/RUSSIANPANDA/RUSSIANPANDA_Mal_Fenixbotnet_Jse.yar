rule RUSSIANPANDA_Mal_Fenixbotnet_Jse
{
	meta:
		description = "Detects Fenix Botnet JSE downloader"
		author = "RussianPanda"
		id = "00c6f8a6-c2e2-5b08-b332-b91371060bbe"
		date = "2024-01-18"
		modified = "2024-02-02"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/d6b1e8ac1e4cbf548804bd84e5f63f3f426b9738/FenixBotnet/mal_FenixBotnet_jse.yar#L1-L14"
		license_url = "N/A"
		hash = "a7fadf0050d4d0b2cefd808e16dfde69"
		logic_hash = "848c00361fba60e63e8ec4098404e87d4ba2b11d8489ad16d49c20fc653a5e45"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = {76 61 72 20 [0-30] 3D 20 22 66 22}
		$s2 = {76 61 72 20 [0-30] 3D 20 22 75 22}
		$s3 = {76 61 72 20 [0-30] 3D 20 22 6E 22}
		$s4 = {6E 65 77 20 46 75 6E 63 74 69 6F 6E 28 64 65 63 6F 64 65 55 52 49 43 6F 6D 70 6F 6E 65 6E 74 28 [0-30] 29 29 2E 63 61 6C 6C 28 29}

	condition:
		all of ($s*)
}
