import "dotnet"

rule DR4K0NIA_Msil_Suspicious_Use_Of_Strreverse : FILE
{
	meta:
		description = "Detects mixed use of Microsoft.CSharp and VisualBasic to use StrReverse"
		author = "dr4k0nia"
		id = "6d4682c3-b372-5d9e-bd6b-747c63e507c6"
		date = "2023-01-31"
		modified = "2023-02-22"
		reference = "https://github.com/dr4k0nia/yara-rules"
		source_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/dotnet/msil_suspicious_use_of_strreverse.yar#L3-L26"
		license_url = "https://github.com/dr4k0nia/yara-rules/blob/4b10f9b79a4cfb3ec9cb5675f32cc7ee6885fbd8/LICENSE.md"
		hash = "02ce0980427dea835fc9d9eed025dd26672bf2c15f0b10486ff8107ce3950701"
		logic_hash = "ce44f1df536104134303b705bda5798dd14dc413296636f2380ecf5811dd63b7"
		score = 60
		quality = 55
		tags = "FILE"
		version = "1.1"

	strings:
		$csharp = "Microsoft.CSharp"
		$vbnet = "Microsoft.VisualBasic"
		$strreverse = "StrReverse"

	condition:
		uint16(0)==0x5a4d and dotnet.is_dotnet and filesize <50MB and $csharp and $vbnet and $strreverse
}
