rule EMBEERESEARCH_Win_Orcus_Rat_Simple_Strings_Dec_2023
{
	meta:
		description = "Strings observed in Orcus RAT"
		author = "Matthew @ Embee_Research"
		id = "baef6b96-bf94-5363-9186-9761a8055afd"
		date = "2023-12-24"
		modified = "2023-12-24"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_orcus_rat_simple_strings_dec_2023.yar#L1-L26"
		license_url = "N/A"
		hash = "30a2a674d55d7898d304713dd2f69a043d875230ea7ebee22596ba4c640768db"
		logic_hash = "2e0a44ec2749e0fc646dfb003a2d32b3fecfa07ece72ca5a65116250d80496b8"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "Orcus is a Remote Administration Tool for Windows. It allows the administrator to make changes to the system remotely." wide
		$s2 = "Orcus.Service" wide
		$s4 = "costura.orcus" wide
		$s5 = "Orcus.Commands"
		$s6 = "Orcus.Shared"
		$s7 = "Orcus.Utilities"
		$s8 = "Orcus.StaticCommands"
		$s9 = "Orcus.Plugins"

	condition:
		(5 of them )
}