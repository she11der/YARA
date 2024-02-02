rule VOLEXITY_Trojan_Win_Iis_Shellsave___XEGroup
{
	meta:
		description = "Detects an AutoIT backdoor designed to run on IIS servers and to install a webshell. This rule will only work against memory samples."
		author = "threatintel@volexity.com"
		id = "a89defa5-4b22-5650-a0c0-f4b3cf3377a7"
		date = "2021-11-17"
		modified = "2021-12-07"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/2021/2021-12-06 - XEGroup/indicators/yara.yar#L22-L40"
		license_url = "https://github.com/volexity/threat-intel/blob/af57cbbbd67525bf8ba24e1df4797799165b6f83/LICENSE.txt"
		logic_hash = "f34d6f4ecaa4cde5965f6b0deac55c7133a2be96f5c466f34775be6e7f730493"
		score = 75
		quality = 80
		tags = ""
		hash1 = "21683e02e11c166d0cf616ff9a1a4405598db7f4adfc87b205082ae94f83c742"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "getdownloadshell" ascii
		$s2 = "deleteisme" ascii
		$s3 = "sitepapplication" ascii
		$s4 = "getapplicationpool" ascii

	condition:
		all of them
}