import "dotnet"

rule EMBEERESEARCH_Win_Asyncrat_Unobfuscated : FILE
{
	meta:
		description = "Detects strings present in unobfuscated AsyncRat Samples. Rule may also pick up on other Asyncrat-derived malware (Dcrat/venom etc)"
		author = "Matthew @ Embee_Research"
		id = "47560ed4-c640-50a1-a0bb-8955e64e39cf"
		date = "2023-08-27"
		modified = "2023-10-18"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_asyncrat_unobfuscated_aug_2023.yar#L3-L29"
		license_url = "N/A"
		hash = "db84db8c5d76f6001d5503e8e4b16cdd3446d5535c45bbb0fca76cfec40f37cc"
		logic_hash = "eadd89cd3fb1515a75b94745089e1cb18977ac34c2242fd0627bf4439fc4089b"
		score = 75
		quality = 75
		tags = "FILE"

	condition:
		dotnet.is_dotnet and filesize <7000KB and ( for any class in dotnet.classes : (class.namespace=="Client.Algorithm") and for any class in dotnet.classes : (class.namespace=="Client.Connection") and for any class in dotnet.classes : (class.namespace=="Client.Helper") and for any class in dotnet.classes : (class.namespace=="Client.Install"))
}
