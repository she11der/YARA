rule VOLEXITY_Apt_Win_Powerstar_Decrypt_Function : CharmingKitten
{
	meta:
		description = "Detects PowerStar decrypt function, potentially downloaded standalone and then injected."
		author = "threatintel@volexity.com"
		id = "1fbc2689-8169-53b1-b581-c41ab2b3a16f"
		date = "2023-05-16"
		modified = "2023-09-20"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2023/2023-06-28 POWERSTAR/indicators/rules.yar#L98-L121"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "d022e363464488836a1c161f2b9c7463ac91ae6f60f14dfd574189233201c9aa"
		score = 75
		quality = 80
		tags = ""
		hash1 = "b79d28fe5e3c988bb5aadb12ce442d53291dbb9ede0c7d9d64eec078beba5585"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$f_1 = "function Borjol{"
		$s_1 = "$global:Domain = \""
		$s_2 = "$global:IP = \""
		$s_3 = "$global:yeolsoe"
		$s_4 = "$semii.Close()"
		$s_5 = "$cemii.Close()"
		$s_6 = "$memii.Close()"

	condition:
		any of ($f_*) or 2 of ($s_*)
}
