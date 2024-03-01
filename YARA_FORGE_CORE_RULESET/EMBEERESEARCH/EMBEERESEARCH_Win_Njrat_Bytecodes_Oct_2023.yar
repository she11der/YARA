import "dotnet"

rule EMBEERESEARCH_Win_Njrat_Bytecodes_Oct_2023
{
	meta:
		description = ""
		author = "Matthew @ Embee_Research"
		id = "9e39587a-e878-5f99-806f-e9964952f0ac"
		date = "2023-10-03"
		modified = "2023-10-03"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_njrat_bytecodes_oct_2023.yar#L3-L22"
		license_url = "N/A"
		hash = "59d6e2958780d15131c102a93fefce6e388e81da7dc78d9c230aeb6cab7e3474"
		hash = "4c56ade4409add1d78eac3b202a9fbd6afbd71878c31f798026082467ace2628"
		hash = "d5a78790a1b388145424327e78f019584466d30d2d450bba832c0128aa3cd274"
		logic_hash = "7df39219e2f2da55e461b1536e92ab125d488a048e41daaaa1fb9516be395d10"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = {14 80 ?? ?? ?? ?? 16 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 14 80 ?? ?? ?? ?? 73 ?? ?? ?? ?? 80 ?? ?? ?? ?? 20 ?? ?? ?? ?? 8D ?? ?? ?? ?? 80 ?? ?? ?? ?? 72 ?? ?? ?? ?? 80 ?? ?? ?? ?? 14 80 ?? ?? ?? ?? 2A }

	condition:
		dotnet.is_dotnet and $s1
}
