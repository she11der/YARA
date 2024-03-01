rule SIGNATURE_BASE_CN_Honker_Hconstfportable : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HconSTFportable.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "591cbd4a-0035-5903-a7dc-8f8ee6dc9f50"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1502-L1517"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "00253a00eadb3ec21a06911a3d92728bbbe80c09"
		logic_hash = "d4368994d38b87a4c0a53321a468fa8a72411ccb17befa0bbc62bdd6de9e1a52"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "HconSTFportable.exe" fullword wide
		$s2 = "www.Hcon.in" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <354KB and all of them
}
