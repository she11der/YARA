import "dotnet"

rule EMBEERESEARCH_Win_Njrat_Strings_Oct_2023
{
	meta:
		description = ""
		author = "Matthew @ Embee_Research"
		id = "c89711cb-aae9-5409-80c2-145a8d5fca56"
		date = "2023-10-03"
		modified = "2023-10-03"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_njrat_strings_oct_2023.yar#L3-L25"
		license_url = "N/A"
		hash = "59d6e2958780d15131c102a93fefce6e388e81da7dc78d9c230aeb6cab7e3474"
		logic_hash = "ed36a991aa2699486f1ef34f4f4d559a3dd351180602f017ad7d868e146c703b"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "netsh firewall delete allowedprogram" wide
		$s2 = "cmd.exe /c ping 0 -n 2 & del" wide
		$s3 = "netsh firewall add allowedprogram" wide
		$s4 = "Execute ERROR" wide
		$s5 = "Update ERROR" wide
		$s6 = "Download ERROR" wide

	condition:
		dotnet.is_dotnet and ( all of ($s*))
}
