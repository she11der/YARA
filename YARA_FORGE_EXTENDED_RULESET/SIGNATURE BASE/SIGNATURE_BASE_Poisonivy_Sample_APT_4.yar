rule SIGNATURE_BASE_Poisonivy_Sample_APT_4 : FILE
{
	meta:
		description = "Detects a PoisonIvy Sample APT"
		author = "Florian Roth (Nextron Systems)"
		id = "02bf546b-99a2-5ffb-8ee7-7bb005ef953b"
		date = "2015-06-03"
		modified = "2023-12-05"
		reference = "VT Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_poisonivy.yar#L79-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "558f0f0b728b6da537e2666fbf32f3c9c7bd4c0c"
		logic_hash = "7ba10269d31e985dff582ae4103ef1179172ae475e078161864f185380bb5035"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Microsoft Software installation Service" fullword wide
		$s1 = "idll.dll" fullword ascii
		$s2 = "mgmts.dll" fullword wide
		$s3 = "Microsoft(R) Windows(R)" fullword wide
		$s4 = "ServiceMain" fullword ascii
		$s5 = "Software installation Service" fullword wide
		$s6 = "SetServiceStatus" fullword ascii
		$s7 = "OriginalFilename" fullword wide
		$s8 = "ZwSetInformationProcess" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 7 of them
}
