rule RUSSIANPANDA_Fenixbotnet_Jse___FILE
{
	meta:
		description = "Detects Fenix Botnet JSE downloader"
		author = "RussianPanda"
		id = "b0dd2f49-ee81-5e8b-a8ef-f00ca03dd452"
		date = "2024-01-18"
		modified = "2024-01-18"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/FenixBotnet/FenixBotnet_jse.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "10bfefed055467aea5c4521c2e586dd3347f5f9fbe6cd12ebea3f94bc5e63dfa"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = {76 61 72 20 [0-30] 3D 20 22 66 22}
		$s2 = {76 61 72 20 [0-30] 3D 20 22 75 22}
		$s3 = {76 61 72 20 [0-30] 3D 20 22 6E 22}
		$s4 = {6E 65 77 20 46 75 6E 63 74 69 6F 6E 28 64 65 63 6F 64 65 55 52 49 43 6F 6D 70 6F 6E 65 6E 74 28 [0-30] 29 29 2E 63 61 6C 6C 28 29}

	condition:
		all of ($s*) and filesize <500KB
}