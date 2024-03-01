rule SIGNATURE_BASE_CN_Honker_MAC_IPMAC : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file IPMAC.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5424d3a7-765a-5dfb-9177-d5633f83079f"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L10-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "24d55b6bec5c9fff4cd6f345bacac7abadce1611"
		logic_hash = "395dfb840346bbf3f68fa198e76349cf65c703b28fd168b85d846d07df1845fe"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Http://Www.YrYz.Net" fullword wide
		$s2 = "IpMac.txt" fullword ascii
		$s3 = "192.168.0.1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <267KB and all of them
}
