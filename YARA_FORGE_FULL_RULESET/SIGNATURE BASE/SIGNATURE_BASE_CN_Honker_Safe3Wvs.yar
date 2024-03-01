rule SIGNATURE_BASE_CN_Honker_Safe3Wvs : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Safe3WVS.EXE"
		author = "Florian Roth (Nextron Systems)"
		id = "035ecb73-3dbc-55d2-8d0c-b71308094d18"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L1644-L1662"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fee3acacc763dc55df1373709a666d94c9364a7f"
		logic_hash = "803591fa9427c3001f78ae6274076f3a2f070770d568909d6cba8cee5124ee4c"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "2TerminateProcess" fullword ascii
		$s1 = "mscoreei.dll" fullword ascii
		$s7 = "SafeVS.exe" fullword wide
		$s8 = "www.safe3.com.cn" fullword wide
		$s20 = "SOFTWARE\\Classes\\Interface\\" ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
