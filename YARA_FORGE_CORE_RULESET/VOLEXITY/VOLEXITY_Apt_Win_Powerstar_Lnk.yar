rule VOLEXITY_Apt_Win_Powerstar_Lnk : CharmingKitten
{
	meta:
		description = "Detects LNK command line used to install PowerStar."
		author = "threatintel@volexity.com"
		id = "33f16283-69b9-5109-b723-3ddc8abb8c41"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L80-L97"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "da53aeaf69e80f697068779f4741b8c23cff82dd1bfb0640916a1bcc98c4892f"
		score = 75
		quality = 80
		tags = ""
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$p_1 = "-UseBasicParsing).Content; &(gcm i*x)$"
		$c_1 = "powershecde43ell.ecde43exe"
		$c_2 = "wgcde43eet -Ucde43eri"
		$c_3 = "-UseBasicde43ecParsing).Contcde43eent; &(gcm i*x)$"

	condition:
		any of them
}
