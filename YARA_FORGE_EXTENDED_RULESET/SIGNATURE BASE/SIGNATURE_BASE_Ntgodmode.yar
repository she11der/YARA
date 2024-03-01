rule SIGNATURE_BASE_Ntgodmode : FILE
{
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "3de620bf-0405-536b-9f6d-3a7f02417b20"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L730-L747"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
		logic_hash = "55efa908ebfcede207d3fe0b1072cce262af0e627e91ba8746e7a8924b8e75bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii
		$s19 = "RtlUnw" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <45KB and all of them
}
