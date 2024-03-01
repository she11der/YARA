rule EMBEERESEARCH_Win_Qakbot_Api_Hashing_Oct_2022 : FILE
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "@Embee_Research"
		id = "b5478404-659d-5b3a-b722-f8ba33875d8a"
		date = "2022-11-14"
		modified = "2022-12-01"
		reference = "https://twitter.com/embee_research/status/1592067841154756610"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/2022/win_qakbot_api_hashing_oct_2022.yar#L2-L21"
		license_url = "N/A"
		logic_hash = "595cabd508ee60c5606f965eb9a290ae21ea32af0f56e213f6ce2d2e35dc4e11"
		score = 75
		quality = 75
		tags = "FILE"
		vendor = "Huntress Labs"

	strings:
		$qakbot_hashing = {0f b6 04 39 33 f0 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 8b c6 c1 ee 04 83 e0 0f 33 34 85 ?? ?? ?? ?? 41 3b ca}

	condition:
		any of them
}
