rule SIGNATURE_BASE_CN_Honker_T00Ls_Lpk_Sethc_V4_LPK : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		author = "Florian Roth (Nextron Systems)"
		id = "808f5de2-1360-521e-8939-b759e361507c"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L2091-L2108"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2b2ab50753006f62965bba83460e3960ca7e1926"
		logic_hash = "a7382d61b53706ad51b36bc686a1c3f0018ee111bdc8ae9b05af144230dfbba3"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "http://127.0.0.1/1.exe" fullword wide
		$s2 = "FreeHostKillexe.exe" fullword ascii
		$s3 = "\\sethc.exe /G everyone:F" ascii
		$s4 = "c:\\1.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of them
}
