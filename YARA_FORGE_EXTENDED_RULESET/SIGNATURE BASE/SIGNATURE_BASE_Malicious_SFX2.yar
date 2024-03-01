rule SIGNATURE_BASE_Malicious_SFX2 : FILE
{
	meta:
		description = "SFX with adobe.exe content"
		author = "Florian Roth (Nextron Systems)"
		id = "ff59d638-4d82-5a14-b346-3df2154d3c34"
		date = "2015-07-20"
		modified = "2023-12-05"
		reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3950"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_minidionis.yar#L55-L70"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "502e42dc99873c52c3ca11dd3df25aad40d2b083069e8c22dd45da887f81d14d"
		logic_hash = "a2ed7660604ff3c9f2d0dbb454f5d168cd61d1d5e647b5c74fe24f25ebb3dbfd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "adobe.exe" fullword ascii
		$s2 = "Extracting files to %s folder$Extracting files to temporary folder" fullword wide
		$s3 = "GETPASSWORD1" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
