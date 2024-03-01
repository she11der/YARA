rule SIGNATURE_BASE_CN_Honker_IIS6_Iis6 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis6.com"
		author = "Florian Roth (Nextron Systems)"
		id = "f5d49cbd-1aec-5126-ab5d-83e485fa6869"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/cn_pentestset_tools.yar#L773-L790"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f0c9106d6d2eea686fd96622986b641968d0b864"
		logic_hash = "51b2fdae6437d64661f20342711d516201740eceb2273704a6e415be2cac54f6"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "GetMod;ul" fullword ascii
		$s1 = "excjpb" fullword ascii
		$s2 = "LEAUT1" fullword ascii
		$s3 = "EnumProcessModules" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
