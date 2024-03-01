rule SIGNATURE_BASE_CN_Honker_Exp_Win2003 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file win2003.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f64e14dd-714c-5a0f-923d-23a584fe605f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1335-L1351"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "47164c8efe65d7d924753fadf6cdfb897a1c03db"
		logic_hash = "d1616c53b26eefaa2578efb7defee182e8c88c869cfffb16c8767ddc1869ad46"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s4 = "Not Windows NT family OS." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
