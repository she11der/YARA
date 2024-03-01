rule SIGNATURE_BASE_CN_Honker_Windows_Mstsc_Enhanced_RMDSTC : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file RMDSTC.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f6e94327-cb79-5a7a-88bb-850177558978"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1228-L1243"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3ca2b1b6f31219baf172abcc8f00f07f560e465f"
		logic_hash = "de676b033613beebfe9fc5a71cf5f5911f0af35d34e77d56d222c6f00114dfb6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "zava zir5@163.com" fullword wide
		$s1 = "By newccc" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
