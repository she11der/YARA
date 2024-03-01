rule EMBEERESEARCH_Win_Darkgate_Xllloader_Oct_2023
{
	meta:
		description = "Detects XLL Files Related to DarkGate"
		author = "Matthew @ Embee_Research"
		id = "4b5d9a2d-90ee-5452-83be-1677e1888045"
		date = "2023-10-03"
		modified = "2023-10-04"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/43c416f765a66a6a514addac7d484c9b652e35a7/Rules/win_darkgate_xll_loader_oct_2023.yar#L2-L23"
		license_url = "N/A"
		hash = "091b7c16791cf976e684fe22ee18a4099a4e26ec75fa145b85dd14603b466b00"
		hash = "305de78353b0d599cd40a73c7e639df7f5946d1fc36691c8f7798a99ee6835e7"
		hash = "98c59262ad396b4da5b0a3e82f819923f860e974f687c4fff9b852f25a56c50f"
		hash = "27ec297e1fc34e29963303782ff881e74f8bd4126f4c5be0c4754f745d85f79a"
		hash = "392fd4d218a8e333bc422635e48fdfae59054413c7a6be764c0275752d45ab23"
		hash = "9a34b32d0a66dd4f59aeea82ef48f335913c47c6ca901ab109df702cd166892f"
		logic_hash = "ea9a166550c53225b0a06e2cd86760f63aed8973e889a457470bdba3d87ce6af"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s1 = "xlAutoOpen" wide ascii
		$s2 = { 49 ?? ?? 4c ?? ?? 48 ?? ?? 48 ?? ?? 02 e8 ?? ?? ?? ?? 48 ?? ?? 31 ?? 48 ?? ?? 01 48 ?? ?? 41 ?? ?? ?? ?? 30 ?? 48 ?? ?? 01 49 ?? ?? 75 ?? }

	condition:
		( all of ($s*))
}
