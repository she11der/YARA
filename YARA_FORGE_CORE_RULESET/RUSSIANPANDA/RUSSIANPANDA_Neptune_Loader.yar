rule RUSSIANPANDA_Neptune_Loader : FILE
{
	meta:
		description = "Detects Neptune Loader"
		author = "RussianPanda"
		id = "31c68d6d-482d-5138-b191-052664125514"
		date = "2024-01-17"
		modified = "2024-01-17"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/NeptuneLoader/neptune_loader.yar#L1-L18"
		license_url = "N/A"
		logic_hash = "97d20f5ac50807a856e356c1610f52bfe3676bce9021ea673edf8eafe5d009f3"
		score = 75
		quality = 81
		tags = "FILE"

	strings:
		$s1 = {8B C6 E8 F4 FB FF FF}
		$s2 = {66 33 D1 66 89 54 58 FE}
		$s3 = {7C 53 74 61 72 74 75 70 46 6F 6C 64 65 72 7C}
		$s4 = {44 65 6C 70 68 69}
		$t1 = {C7 [3] 0B 40 40 00 [6] A1 ?? 61 40 00}
		$t2 = {C7 ?? 24 00 40 40 00 A1 ?? 61 40 00}
		$t3 = {8B ?? ?? FF D0 B8}

	condition:
		3 of ($s*) or 2 of ($t*) and filesize <6MB
}
