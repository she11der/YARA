rule SIGNATURE_BASE_CN_Honker_Swordcolledition : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordCollEdition.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4e8d4d48-c053-5579-be9c-af73ec0fe614"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1485-L1500"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6e14f21cac6e2aa7535e45d81e8d1f6913fd6e8b"
		logic_hash = "bbc5c9bb91bdd60582e2d7f6fa9b1a1cc3799e0809b670d575d9b2c77bf5e884"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "YuJianScan.exe" fullword wide
		$s1 = "YuJianScan" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <225KB and all of them
}
