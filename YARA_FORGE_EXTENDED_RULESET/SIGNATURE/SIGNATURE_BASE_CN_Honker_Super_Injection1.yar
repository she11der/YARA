rule SIGNATURE_BASE_CN_Honker_Super_Injection1 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file super Injection1.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ad84c5a0-4f03-5040-bdf7-819b40a08ad2"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L2148-L2164"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8ff2df40c461f6c42b92b86095296187f2b59b14"
		logic_hash = "11a3628b7c34a34dc37604430195e24063d3f0dd0889d6d782ce0ee42cafbb02"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Invalid owner=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
		$s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
		$s4 = "ScanInject.log" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
