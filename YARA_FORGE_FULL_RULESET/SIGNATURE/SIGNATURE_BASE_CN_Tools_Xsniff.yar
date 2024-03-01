rule SIGNATURE_BASE_CN_Tools_Xsniff : FILE
{
	meta:
		description = "Chinese Hacktool Set - file xsniff.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "a0fdac88-a7b8-5d24-9012-2bfe7b07e675"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L1087-L1104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d61d7329ac74f66245a92c4505a327c85875c577"
		logic_hash = "a32d07ecd635ad71edaa37d9b1e5f66d8ce5a7f84f1bba6eb06deb1f49a879c8"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "xsiff.exe -pass -hide -log pass.log" fullword ascii
		$s1 = "HOST: %s USER: %s, PASS: %s" fullword ascii
		$s2 = "xsiff.exe -tcp -udp -asc -addr 192.168.1.1" fullword ascii
		$s10 = "Code by glacier <glacier@xfocus.org>" fullword ascii
		$s11 = "%-5s%s->%s Bytes=%d TTL=%d Type: %d,%d ID=%d SEQ=%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <220KB and 2 of them
}
