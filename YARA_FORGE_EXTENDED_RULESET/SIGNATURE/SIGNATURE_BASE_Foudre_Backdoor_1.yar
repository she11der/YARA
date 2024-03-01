import "pe"

rule SIGNATURE_BASE_Foudre_Backdoor_1 : FILE
{
	meta:
		description = "Detects Foudre Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "ab2d43f4-fc35-5980-9b5d-98c5c4cfd012"
		date = "2017-08-01"
		modified = "2023-12-05"
		reference = "https://goo.gl/Nbqbt6"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_foudre.yar#L13-L29"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e42959162017ddf6da1d0b2950096e93e0e98c3e5f88ae28fc48e82ef98ca87b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "7e73a727dc8f3c48e58468c3fd0a193a027d085f25fa274a6e187cf503f01f74"
		hash2 = "7ce2c5111e3560aa6036f98b48ceafe83aa1ac3d3b33392835316c859970f8bc"

	strings:
		$s1 = "initialization failed: Reinstall the program" fullword wide
		$s2 = "SnailDriver V1" fullword wide
		$s3 = "lp.ini" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 2 of them )
}
