rule EMBEERESEARCH_Win_Solarmarker_Stage2_Bytecodes_Dec_2023
{
	meta:
		description = "Patterns observed in Solarmarker stage2 dll"
		author = "Matthew @ Embee_Research"
		id = "9aba6cdf-1491-579d-b4a7-fe229272015d"
		date = "2023-12-28"
		modified = "2023-12-28"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_solarmarker_stage2_bytecodes_dec_2023.yar#L1-L20"
		license_url = "N/A"
		hash = "4a3b60496a793ee96a51fecf8690ef8312429a6b54d32f2a4424395c47b47fc8"
		hash = "e0b2457491a8c2d50710aa343ad1957a76f83ceaf680165ffa0e287fe18abbd6"
		logic_hash = "8e50e5942f0029ffda1d9750f8cc8e004a2512e50b6a14c1619ae0b83477a944"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {6F ?? ?? 00 0A 1F 20 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 09 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 0A 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 0D 2E ?? 02 7B ?? ?? 00 04 02 7B ?? ?? 00 04 6F ?? ?? 00 0A 1F 0A }

	condition:
		$s1
}