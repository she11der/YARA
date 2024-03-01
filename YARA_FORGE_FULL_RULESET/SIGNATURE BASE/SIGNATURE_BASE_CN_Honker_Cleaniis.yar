rule SIGNATURE_BASE_CN_Honker_Cleaniis : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cleaniis.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "75f3c33a-e3b8-57bc-a3fd-f8b6491388d8"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1575-L1590"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "372bc64c842f6ff0d9a1aa2a2a44659d8b88cb40"
		logic_hash = "6f3fe22c9ce8b576116a3fc185910488f37b687c1158d49a93feaa68a144a8db"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "iisantidote <logfile dir> <ip or string to hide>" fullword ascii
		$s4 = "IIS log file cleaner by Scurt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
