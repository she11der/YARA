rule SIGNATURE_BASE_Waterbear_11_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "d7eb7561-c84e-5149-920c-35ad225ca8a9"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_waterbear.yar#L185-L201"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ea61c348847614ad2872bfd385f433c5a30c7f6b5f5a2f135a7d83c553157ccd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b046b2e2569636c2fc3683a0da8cfad25ff47bc304145be0f282a969c7397ae8"

	strings:
		$s1 = "/Pages/%u.asp" fullword wide
		$s2 = "NVIDIA Corporation." fullword wide
		$s3 = "tqxbLc|fP_{eOY{eOX{eO" fullword ascii
		$s4 = "Copyright (C) 2005" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
