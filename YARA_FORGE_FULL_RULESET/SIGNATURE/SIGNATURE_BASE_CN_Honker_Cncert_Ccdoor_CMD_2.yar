rule SIGNATURE_BASE_CN_Honker_Cncert_Ccdoor_CMD_2 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file CnCerT.CCdoor.CMD.dll2"
		author = "Florian Roth (Nextron Systems)"
		id = "2681a989-6504-5ac7-abc9-e6dad2a052c5"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1373-L1390"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7f3a6fb30845bf366e14fa21f7e05d71baa1215a"
		logic_hash = "8f33f2999eae3f080e8e5ec51ced3e7d596a07b6e5c9830cc1ca552701ed6502"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cmd.dll" fullword wide
		$s1 = "cmdpath" fullword ascii
		$s2 = "Get4Bytes" fullword ascii
		$s3 = "ExcuteCmd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <22KB and all of them
}
