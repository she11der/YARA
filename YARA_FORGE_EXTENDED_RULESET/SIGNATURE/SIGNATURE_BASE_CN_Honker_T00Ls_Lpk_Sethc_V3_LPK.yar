rule SIGNATURE_BASE_CN_Honker_T00Ls_Lpk_Sethc_V3_LPK : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		author = "Florian Roth (Nextron Systems)"
		id = "c5b806d9-74dc-5244-b1e0-9837abeaeaac"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1519-L1536"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
		logic_hash = "20e949bef1c1631ef2a48c78c2ccc4dcea2f842275ec5df3e31c5d915e8a2a04"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "FreeHostKillexe.exe" fullword ascii
		$s2 = "\\sethc.exe /G everyone:F" ascii
		$s3 = "c:\\1.exe" fullword ascii
		$s4 = "Set user Group Error! Username:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
