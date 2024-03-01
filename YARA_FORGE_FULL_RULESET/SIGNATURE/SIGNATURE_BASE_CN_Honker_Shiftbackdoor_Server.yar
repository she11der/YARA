rule SIGNATURE_BASE_CN_Honker_Shiftbackdoor_Server : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Server.dat"
		author = "Florian Roth (Nextron Systems)"
		id = "c53f4015-ad2b-5898-88b5-34b3bc2c65b6"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1316-L1333"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b24d761c6bbf216792c4833890460e8b37d86b37"
		logic_hash = "17f1d7f2345ed1bc9b240c4851f41891244ec9d13b296a24ab6b42cca32ddf87"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "del /q /f %systemroot%system32sethc.exe" fullword ascii
		$s1 = "cacls %s /t /c /e /r administrators" fullword ascii
		$s2 = "\\dllcache\\sethc.exe" ascii
		$s3 = "\\ntvdm.exe" ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 2 of them
}
