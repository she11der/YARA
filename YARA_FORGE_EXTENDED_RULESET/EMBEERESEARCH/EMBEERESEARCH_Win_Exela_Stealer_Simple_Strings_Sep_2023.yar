import "dotnet"

rule EMBEERESEARCH_Win_Exela_Stealer_Simple_Strings_Sep_2023
{
	meta:
		description = "No description has been set in the source file - EmbeeResearch"
		author = "Matthew @embee_research"
		id = "e63aa1d3-997e-5200-93fc-869c177fe1a8"
		date = "2023-09-24"
		modified = "2023-09-26"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_exela_stealer_simple_strings_sep_2023.yar#L4-L32"
		license_url = "N/A"
		hash = "bf5d70ca2faf355d86f4b40b58032f21e99c3944b1c5e199b9bb728258a95c1b"
		logic_hash = "2312b63fe86fd34eb12f42f079f470eb3af27ef8c199f3620253c828ad28441a"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "https://i.instagram.com/api/v1/accounts/current_user/" wide
		$s2 = "/create /f /sc onlogon /rl highest /tn \"AutoUpdateCheckerOnLogon\" /tr " wide
		$s4 = "https://discord.com/api/webhooks/" wide
		$s5 = "Browser : {0} | Name : {1} | Value : {2} | Date created (timestamp) : {3} |  Date last used (timestamp) : {4} | Count {5}" wide
		$s6 = "Browser : {0} | {1} {2}/{3} {4}" wide
		$e1 = "Exela.Program" wide ascii
		$e2 = "Exela.Wifi" wide ascii
		$e3 = "Exela.Components" wide ascii
		$e4 = "Exela Stealer" wide ascii
		$e5 = "Exela.exe" wide ascii

	condition:
		dotnet.is_dotnet and (( all of ($s*)) or (3 of ($e*)))
}
