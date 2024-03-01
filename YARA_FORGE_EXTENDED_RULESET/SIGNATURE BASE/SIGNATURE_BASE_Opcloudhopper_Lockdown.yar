rule SIGNATURE_BASE_Opcloudhopper_Lockdown : FILE
{
	meta:
		description = "Tools related to Operation Cloud Hopper"
		author = "Florian Roth (Nextron Systems)"
		id = "0500f19c-597b-5904-8401-35236215ff29"
		date = "2017-04-07"
		modified = "2023-12-05"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cloudhopper.yar#L251-L265"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3f24c08817bc94bb4b7d09d51bed62f43952f2c66338f29c4bc8e9000b3ff78a"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "8ca61cef74573d9c1d19b8191c23cbd2b7a1195a74eaba037377e5ee232b1dc5"

	strings:
		$s1 = "lockdown.dll" fullword ascii
		$s3 = "mfeann.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
