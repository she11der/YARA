rule VOLEXITY_Apt_Win_Applejeus_Oct22 : Lazarus
{
	meta:
		description = "Detects AppleJeus DLL samples."
		author = "threatintel@volexity.com"
		id = "f88e2253-e296-57d8-a627-6cb4ccff7a92"
		date = "2022-11-03"
		modified = "2022-12-01"
		reference = "https://github.com/volexity/threat-intel"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2022/2022-12-01 Buyer Beware - Fake Cryptocurrency Applications Serving as Front for AppleJeus Malware/yara.yar#L1-L16"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "46f3325a7e8e33896862b1971f561f4871670842aecd46bcc7a5a1af869ecdc4"
		score = 75
		quality = 80
		tags = ""
		hash1 = "82e67114d632795edf29ce1d50a4c1c444846d9e16cd121ce26e63c8dc4a1629"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$s1 = "HijackingLib.dll" ascii

	condition:
		$s1
}
