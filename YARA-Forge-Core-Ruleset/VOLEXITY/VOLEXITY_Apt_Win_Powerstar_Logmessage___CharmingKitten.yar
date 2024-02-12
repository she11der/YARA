rule VOLEXITY_Apt_Win_Powerstar_Logmessage___CharmingKitten
{
	meta:
		description = "Detects interesting log message embedded in memory only version of PowerStar."
		author = "threatintel@volexity.com"
		id = "5979c776-5138-50e2-adab-0793ad86ba76"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L66-L79"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "539c9a8b3de24f2c8058d204900344756a8031822ebebc312612b8fb8422e341"
		score = 75
		quality = 80
		tags = ""
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "wau, ije ulineun mueos-eul halkkayo?"

	condition:
		all of them
}