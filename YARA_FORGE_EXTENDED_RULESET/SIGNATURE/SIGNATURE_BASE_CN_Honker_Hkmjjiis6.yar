rule SIGNATURE_BASE_CN_Honker_Hkmjjiis6 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hkmjjiis6.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "badf8224-4f09-57aa-ab16-0d70e0b3f88c"
		date = "2015-06-23"
		modified = "2023-01-27"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1701-L1718"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
		logic_hash = "a087b9731444152b717e0fbae557004d94f3fb69a4ec65aa38b7a3dab3e3cddf"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s14 = "* FROM IIsWebInfo/r" fullword ascii
		$s19 = "ltithread4ck/" ascii
		$s20 = "LookupAcc=Sid#" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <175KB and all of them
}
