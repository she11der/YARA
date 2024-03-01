rule EMBEERESEARCH_Win_Stealc_Bytecodes_Oct_2023
{
	meta:
		description = "Bytecodes present in Stealc decoding routine"
		author = "Matthew @ Embee_Research"
		id = "ecac28a0-cd77-5e6a-8af2-59ea62e733bf"
		date = "2023-08-27"
		modified = "2023-10-09"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_stealc_bytecodes_oct_2023.yar#L2-L21"
		license_url = "N/A"
		hash = "74ff68245745b9d4cec9ef3c539d8da15295bdc70caa6fdb0632acdd9be4130a"
		hash = "9f44a4cbc30e7a05d7eb00b531a9b3a4ada5d49ecf585b48892643a189358526"
		logic_hash = "d50f57e32a7f513d92625549fcd139b7fa1e478879283fd61426fcd19d03d296"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {8b 4d f0 89 4d f8 8b 45 f8 c1 e0 03 33 d2 b9 06 00 00 00 f7 f1 8b e5 5d c2 04 00}

	condition:
		( all of ($s*))
}
