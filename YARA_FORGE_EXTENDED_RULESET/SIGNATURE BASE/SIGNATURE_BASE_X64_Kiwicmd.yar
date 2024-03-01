rule SIGNATURE_BASE_X64_Kiwicmd : FILE
{
	meta:
		description = "Chinese Hacktool Set - file KiwiCmd.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "df759fd4-5d42-5dd9-81d0-ceccafcdd64d"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1682-L1697"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "569ca4ff1a5ea537aefac4a04a2c588c566c6d86"
		logic_hash = "b49a70a49a67fbb57d643b38155482177f594bd1f01f5464c4f36b265aac48d8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Process Ok, Memory Ok, resuming process :)" fullword wide
		$s2 = "Kiwi Cmd no-gpo" fullword wide
		$s3 = "KiwiAndCMD" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 2 of them
}
