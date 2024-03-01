rule SIGNATURE_BASE_CN_Honker_DLL_Passive_Privilege_Escalation_Ws2Help : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ws2help.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "85a07bb7-2856-56f0-bd15-e020bb2a7692"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L470-L485"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "e539b799c18d519efae6343cff362dcfd8f57f69"
		logic_hash = "e13f33e48d5c1aeaef6c50287f74e03fb7b65667d597768d448e76f5a375b34f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PassMinDll.dll" fullword ascii
		$s1 = "\\ws2help.dll" ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of them
}
