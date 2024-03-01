rule EMBEERESEARCH_Win_Ursnif_Patterns_Oct_2022
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Embee_Research @ Huntress"
		id = "2c8da2b7-63f2-5cce-86ab-8a88f50d0263"
		date = "2022-10-14"
		modified = "2023-06-14"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_ursnif_patterns_oct_2022.yar#L1-L14"
		license_url = "N/A"
		logic_hash = "241804ea3b7ac98071c533d9a98a45cdd0f7043f11994327c1f79e29f5fdce2c"
		score = 75
		quality = 75
		tags = ""

	strings:
		$ursnif = {41 c1 e8 02 45 33 d2 45 8b d9 45 85 c0 74 2f 48 2b ca 83 7c 24 28 00 8b 04 11 44 8b c8 74 0a 85 c0 75 06 44 8d 40 01}
		$script = "65,193,232,2,69,51,210,69,139,217,69,133,192,116,47,72,43,202,131,124,36,40,0,139,4,17,68,139,200,116,10,133,192,117,6,68,141,64,1"

	condition:
		any of them
}
