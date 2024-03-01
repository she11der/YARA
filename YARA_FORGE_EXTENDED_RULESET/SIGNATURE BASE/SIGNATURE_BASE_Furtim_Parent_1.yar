rule SIGNATURE_BASE_Furtim_Parent_1 : FILE
{
	meta:
		description = "Detects Furtim Parent Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "a47719d2-1e4f-50a9-b340-55e13f5a24d5"
		date = "2016-07-16"
		modified = "2023-12-05"
		reference = "https://sentinelone.com/blogs/sfg-furtims-parent/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_furtim.yar#L34-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ab4c7ca5c887b2a2f2949a5a6fd0d623dad47d9c1f866fb43f7f8ec38dfa6a02"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "766e49811c0bb7cce217e72e73a6aa866c15de0ba11d7dda3bd7e9ec33ed6963"

	strings:
		$x1 = "dqrChZonUF" fullword ascii
		$s1 = "Egistec" fullword wide
		$s2 = "Copyright (C) 2016" fullword wide
		$op1 = { c0 ea 02 88 55 f8 8a d1 80 e2 03 }
		$op2 = { 5d fe 88 55 f9 8a d0 80 e2 0f c0 }
		$op3 = { c4 0c 8a d9 c0 eb 02 80 e1 03 88 5d f8 8a d8 c0 }

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and ($x1 or ( all of ($s*) and all of ($op*)))) or all of them
}
