import "dotnet"

rule EMBEERESEARCH_Win_Njrat_Bytecodes_V2_Oct_2023
{
	meta:
		description = ""
		author = "Matthew @ Embee_Research"
		id = "9090574e-7ad4-5207-af8b-7b56f2a1c917"
		date = "2023-10-03"
		modified = "2023-10-08"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_njrat_bytecodes_v2_oct_2023.yar#L5-L27"
		license_url = "N/A"
		hash = "9877fc613035d533feda6adc6848e183bf8c8660de3a34b1acd73c75e62e2823"
		hash = "40f07bdfb74e61fe7d7973bcd4167ffefcff2f8ba2ed6f82e9fcb5a295aaf113"
		logic_hash = "0bdbf5715e3873d96c88a24ba08487af2b798d26cdcd3e35d783ce4828dae775"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {03 1F 72 2E ?? 03 1F 73 2E ?? 03 1F 74 2E ?? 03 1F 75 2E ?? 03 1F 76 2E ?? }
		$s2 = {0B 14 0C 16 0D 16 13 ?? 16 13 ?? 14}

	condition:
		dotnet.is_dotnet and ( all of ($s*))
}
