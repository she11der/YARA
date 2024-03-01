rule ARKBIRD_SOLG_Mem_Cryptor_Obsidium_Oct_2020_1 : FILE
{
	meta:
		description = "Detect Obsidium cryptor by memory string"
		author = "Arkbird_SOLG"
		id = "039c45f0-cc43-50ee-ae4e-a7e0e220dc04"
		date = "2020-10-25"
		modified = "2020-10-27"
		reference = "Internal Research"
		source_url = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-10-27/RYUK/Mem_Cryptor_Obsidium_Oct_2020_1.yar#L1-L15"
		license_url = "N/A"
		logic_hash = "5f471064505d7ab634b6d52f66fa0a96682af2eb1dd41afe4449543253c6bbf7"
		score = 75
		quality = 50
		tags = "FILE"

	strings:
		$s1 = "Obsidium\\" fullword ascii
		$s2 = "obsidium.dll" fullword ascii
		$s3 = "Software\\Obsidium" fullword ascii
		$s4 = "winmm.dll" fullword ascii
		$s5 = "'license.key" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize >40KB and 3 of ($s*)
}
