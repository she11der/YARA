rule SIGNATURE_BASE_CN_Honker_MSTSC_Can_Direct_Copy : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSC_can_direct_copy.EXE"
		author = "Florian Roth (Nextron Systems)"
		id = "9155cb6f-14b6-524a-9cb9-1a88f7facf4e"
		date = "2015-06-23"
		modified = "2022-12-21"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L951-L968"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2f3cbfd9f82f8abafdb1d33235fa6bfa1e1f71ae"
		logic_hash = "5437abd979a8df5ee3f8508f7a5fff85714b5d8a22ab1760fe1e7a8168a8c255"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "srv\\newclient\\lib\\win32\\obj\\i386\\mstsc.pdb" ascii
		$s2 = "Clear Password" fullword wide
		$s3 = "/migrate -- migrates legacy connection files that were created with " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
