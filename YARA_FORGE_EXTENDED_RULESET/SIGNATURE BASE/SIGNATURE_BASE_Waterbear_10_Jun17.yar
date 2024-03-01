rule SIGNATURE_BASE_Waterbear_10_Jun17 : FILE
{
	meta:
		description = "Detects malware from Operation Waterbear"
		author = "Florian Roth (Nextron Systems)"
		id = "1219c3e6-1001-5075-b7fc-e0d8a7de6a65"
		date = "2017-06-23"
		modified = "2023-12-05"
		reference = "https://goo.gl/L9g9eR"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_waterbear.yar#L168-L182"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1e71a317f782b73c876f0cb5fee25b69d8f1c45c20c58e4f204b7aeb7484cf14"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3b1e67e0e86d912d7bc6dee5b0f801260350e8ce831c93c3e9cfe5a39e766f41"

	strings:
		$s1 = "ADVPACK32.DLL" fullword wide
		$s5 = "ADVPACK32" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <30KB and all of them )
}
