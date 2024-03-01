rule SIGNATURE_BASE_Poisonivy_Sample_APT : FILE
{
	meta:
		description = "Detects a PoisonIvy APT malware group"
		author = "Florian Roth (Nextron Systems)"
		id = "8d3b8222-8949-57dc-99b7-092189416efd"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poisonivy.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b874b76ff7b281c8baa80e4a71fc9be514093c70"
		logic_hash = "938df757d1f5ee1028d61dbc2ab76a33c788a44f87cb0d84626420e20bfb5fa4"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "pidll.dll" fullword ascii
		$s1 = "sens32.dll" fullword wide
		$s3 = "FileDescription" fullword wide
		$s4 = "OriginalFilename" fullword wide
		$s5 = "ZwSetInformationProcess" fullword ascii
		$s9 = "Microsoft Media Device Service Provider" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <47KB and all of them
}
