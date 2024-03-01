rule SIGNATURE_BASE_CN_Honker_Fckeditor : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Fckeditor.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "eb8767cb-b081-5c37-b7ad-57a0de047462"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L525-L540"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4b16ae12c204f64265acef872526b27111b68820"
		logic_hash = "0fd231fc81b2b7b5647a8016774f35751ac68646856a15c17ce4d2c07eaf1761"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "explorer.exe http://user.qzone.qq.com/568148075" fullword wide
		$s7 = "Fckeditor.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1340KB and all of them
}
