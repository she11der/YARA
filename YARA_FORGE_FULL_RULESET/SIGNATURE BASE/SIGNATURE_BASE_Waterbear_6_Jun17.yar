rule SIGNATURE_BASE_Waterbear_6_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "86d203be-2d3a-54f2-b851-9080d5be36f5"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_waterbear.yar#L92-L106"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "af5c2a29e0a62c54e706492ae85b9786a6d9e5f42fe4d9c43693576e1a63b825"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "409cd490feb40d08eb33808b78d52c00e1722eee163b60635df6c6fe2c43c230"

	strings:
		$s1 = "svcdll.dll" fullword ascii
		$s2 = "log.log" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <60KB and all of them )
}
