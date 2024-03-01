rule EMBEERESEARCH_Win_Marsstealer_Encryption_Bytecodes
{
	meta:
		description = "Encryption observed in MarsStealer"
		author = "Matthew @ Embee_Research"
		id = "7a66ea9c-966e-5780-8b36-a268904b9c1b"
		date = "2023-12-24"
		modified = "2023-12-24"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_marsStealer_encryption_bytecodes_dec_2023.yar#L1-L16"
		license_url = "N/A"
		hash = "7a391340b6677f74bcf896b5cc16a470543e2a384049df47949038df5e770df1"
		logic_hash = "49ffde28c8823c00959ddbaa516fc48c7908b533c8f91608b0e3a645045c9048"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {31 2d 3d 31 73 30 02 39 c0 74 0a 5b 70 61 73 64 6c 30 71 77 69 8d 5b 01 8d 52 01 39 eb 75 03 83 eb 20 39 ca}

	condition:
		$s1
}
