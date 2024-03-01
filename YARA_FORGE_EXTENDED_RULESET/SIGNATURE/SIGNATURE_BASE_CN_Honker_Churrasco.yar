rule SIGNATURE_BASE_CN_Honker_Churrasco : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Churrasco.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "58873cd6-0c9e-58a0-923a-aca8a1d42017"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L45-L64"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5a3c935d82a5ff0546eff51bb2ef21c88198f5b8"
		logic_hash = "f60589bda76367578388cbe6af912c80c9364a7047ed52ca2b4156a1b277e7ca"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "HEAD9 /" ascii
		$s1 = "logic_er" fullword ascii
		$s6 = "proggam" fullword ascii
		$s16 = "DtcGetTransactionManagerExA" fullword ascii
		$s17 = "GetUserNameA" fullword ascii
		$s18 = "OLEAUT" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1276KB and all of them
}
