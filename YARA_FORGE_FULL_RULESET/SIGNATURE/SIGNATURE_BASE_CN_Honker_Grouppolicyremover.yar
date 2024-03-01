rule SIGNATURE_BASE_CN_Honker_Grouppolicyremover : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GroupPolicyRemover.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "e581172d-fcea-5281-ba9f-06b35c9a513e"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1100-L1116"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7475d694e189b35899a2baa462957ac3687513e5"
		logic_hash = "936d5dea2d44f638abfb5e42f45c0678bcbf769b575b5056db1a1fc41d1643be"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "GP_killer.EXE" fullword wide
		$s1 = "GP_killer Microsoft " fullword wide
		$s2 = "SHDeleteKeyA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
