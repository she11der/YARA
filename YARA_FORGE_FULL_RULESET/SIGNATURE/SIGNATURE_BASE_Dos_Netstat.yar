rule SIGNATURE_BASE_Dos_Netstat : FILE
{
	meta:
		description = "Chinese Hacktool Set - file netstat.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "bc3141bf-4e82-5aa4-a8a6-a0a4586ee9a1"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1069-L1085"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d0444b7bd936b5fc490b865a604e97c22d97e598"
		logic_hash = "e2b908308616c3f2c94849b4f22f0e9bb130b5759d89161604505ff25681be55"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "w03a2409.dll" fullword ascii
		$s1 = "Retransmission Timeout Algorithm    = unknown (%1!u!)" fullword wide
		$s2 = "Administrative Status  = %1!u!" fullword wide
		$s3 = "Packet Too Big            %1!-10u!  %2!-10u!" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <150KB and all of them
}
