import "dotnet"

rule EMBEERESEARCH_Win_Xworm_Bytestring
{
	meta:
		description = "Detects bytestring present in unobfuscated xworm"
		author = "Matthew @ Embee_Research"
		id = "b7bad89d-ff15-50ae-8c97-64b181dad07f"
		date = "2023-08-27"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_xworm_bytestring_sep_2023.yar#L3-L24"
		license_url = "N/A"
		hash = "8948b34d471db1e334e6caa00492bd11a60d0ec378933386b0cb7bc1b971c102"
		hash = "52634ade55558807042eae35e2777894e405e811102e980a2e2b25d151fde121"
		logic_hash = "dd9955c3616ee65cf94625f5fc92298464a9a3b6deaf32ae70d7e8206c0ceb5b"
		score = 50
		quality = 75
		tags = ""

	strings:
		$p1 = { 72 [4] 16 28 [4] 16 33 ?? 72 [4] 0C 38 [4] 11 ?? 72 [4] 16 28 [4] 16 33 ?? 72 [4] 0C 38 [4] 11 ?? 72 [4] 16 28 [4] 16 33 ?? 72 [4] 0C 38 [4] 11 ?? 72 [4] 16 28 [4] 16 33 ?? }

	condition:
		dotnet.is_dotnet and $p1
}
