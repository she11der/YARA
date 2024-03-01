import "dotnet"

rule EMBEERESEARCH_Win_Xworm_Simple_Strings
{
	meta:
		description = "Detects simple strings present in unobfuscated xworm"
		author = "Matthew @ Embee_Research"
		id = "8d5d8f07-72fa-596b-a3fc-1dee4b7fd058"
		date = "2023-08-30"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_xworm_simple_strings_sep_2023.yar#L3-L29"
		license_url = "N/A"
		hash = "4459d95c0493d640ecc9453cf6a4f2b7538b1a7b95032f70803fc726b8e40422"
		hash = "820bb1a31f421b90ea51efc3e71cc720c8c2784fb1e882e732e8fafb8631a389"
		logic_hash = "f7df310b24b2078249cdb670ece71ebe30f985c92b3e44b6dcf0e37405a26bc3"
		score = 75
		quality = 75
		tags = ""

	strings:
		$x1 = "XWorm V" wide nocase
		$s1 = "/create /f /RL HIGHEST /sc minute /mo 1 /tn " wide
		$s2 = "/create /f /sc minute /mo 1 /tn " wide
		$s3 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath " wide

	condition:
		dotnet.is_dotnet and $x1 and (2 of ($s*))
}
