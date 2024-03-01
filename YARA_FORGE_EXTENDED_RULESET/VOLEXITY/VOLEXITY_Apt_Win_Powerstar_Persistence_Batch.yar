rule VOLEXITY_Apt_Win_Powerstar_Persistence_Batch : CharmingKitten
{
	meta:
		description = "Detects the batch script used to persist PowerStar via Startup."
		author = "threatintel@volexity.com"
		id = "f3ed7b46-d80d-55b1-b6c7-6ea6569f199c"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L1-L19"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "9c3a45b759516959eae1cdf8e73bf540b682c90359a6232aa4782a8d1fe15b7d"
		score = 75
		quality = 80
		tags = ""
		hash1 = "9777f106ac62829cd3cfdbc156100fe892cfc4038f4c29a076e623dc40a60872"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s_1 = "e^c^h^o o^f^f"
		$s_2 = "powershertxdll.ertxdxe"
		$s_3 = "Get-Conrtxdtent -Prtxdath"
		$s_4 = "%appdata%\\Microsrtxdoft\\Windortxdws\\"
		$s_5 = "&(gcm i*x)$"

	condition:
		3 of them
}
