rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Xorist
{
	meta:
		description = "Detects files referencing identities associated with Xorist ransomware"
		author = "ditekShen"
		id = "151d182c-c60a-54dd-a3d2-b32d27521b57"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L1710-L1723"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5975a730ad1a1f7e54e95ec5897aa2940ccc3ed1aa8e83b38cb7ac836c233208"
		score = 75
		quality = 67
		tags = ""

	strings:
		$s1 = "@root_backdoor_synaptics_V" ascii wide nocase
		$s2 = "@DosX_Plus" ascii wide nocase
		$s3 = "@Cinoshi_Adm" ascii wide nocase
		$s4 = "@ac3ss0r" ascii wide nocase
		$s5 = "MCwRK1Z7K4GYHt9ZrbTR2SMCEqzqQaTbRF" ascii wide
		$s6 = "0x334F093c9De6552AF4cC0B252dA82aC77FeB467D" ascii wide

	condition:
		any of them
}
