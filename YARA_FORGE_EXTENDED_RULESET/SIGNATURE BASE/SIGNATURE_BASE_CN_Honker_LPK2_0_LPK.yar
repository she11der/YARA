rule SIGNATURE_BASE_CN_Honker_LPK2_0_LPK : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		author = "Florian Roth (Nextron Systems)"
		id = "4aa40b78-5fe4-5312-881c-e5a292435ff0"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1556-L1573"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5a1226e73daba516c889328f295e728f07fdf1c3"
		logic_hash = "d693b880d5419277d9189d44ace60fe5f328b4662c1975a8bc97e63dc073d1e6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "\\sethc.exe /G everyone:F" ascii
		$s2 = "net1 user guest guest123!@#" fullword ascii
		$s3 = "\\dllcache\\sethc.exe" ascii
		$s4 = "sathc.exe 211" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1030KB and all of them
}
