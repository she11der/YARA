rule SIGNATURE_BASE_CN_Honker_Smsniff_Smsniff : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file smsniff.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "fef242d5-b274-5217-a5d1-1a6ec38d0fdd"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L648-L663"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8667a785a8ced76d0284d225be230b5f1546f140"
		logic_hash = "6949f992d4734f18d9caffe83f2abccca0e0decef4169954518eed078d39e561"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "smsniff.exe" fullword wide
		$s5 = "SmartSniff" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <267KB and all of them
}
