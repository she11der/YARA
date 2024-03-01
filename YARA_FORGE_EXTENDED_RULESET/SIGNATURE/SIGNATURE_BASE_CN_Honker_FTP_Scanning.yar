rule SIGNATURE_BASE_CN_Honker_FTP_Scanning : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file FTP_scanning.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "828a0dc8-3748-5c07-a767-4f9e85968ca1"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L1044-L1061"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5a3543ee5aed110c87cbc3973686e785bcb5c44e"
		logic_hash = "5f1c312dc9fa80c120699bacd17d5e4c147ab96f90c619a8c39ec27646a1307f"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "CNotSupportedE" fullword ascii
		$s2 = "nINet.dll" fullword ascii
		$s9 = "?=MODULE" fullword ascii
		$s13 = "MSIE 6*" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <550KB and all of them
}
