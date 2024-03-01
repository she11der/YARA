import "dotnet"

rule EMBEERESEARCH_Win_Agent_Tesla_Bytecodes_Sep_2023
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Matthew @embee_research"
		id = "9d1c5010-7c64-5a6a-bf60-35c042732761"
		date = "2023-09-21"
		modified = "2023-09-21"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_agent_tesla_bytecodes_sep_2023.yar#L4-L21"
		license_url = "N/A"
		hash = "ce696cf7a6111f5e7c6781854de04ddc262b6c9b39c059fd5435dfb3b8901f04"
		hash = "afc29232c4989587db2c54b7c9f145fd0d73537e045ece15338582ede5389fce"
		hash = "fba4374163ba25c9dc572f1a5d7f3e46e09531ab964d808f3dde2a19c05a2ee5"
		logic_hash = "1cc40ab16dfa5245b3146e4512509037f540d59e155040a2336a97cd0f42e612"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {8F ?? ?? ?? ?? 25 47 FE ?? ?? ?? FE ?? ?? ?? 91 61 D2 52 20 ?? ?? ?? ?? FE ?? ?? ?? }

	condition:
		dotnet.is_dotnet and $s1
}
