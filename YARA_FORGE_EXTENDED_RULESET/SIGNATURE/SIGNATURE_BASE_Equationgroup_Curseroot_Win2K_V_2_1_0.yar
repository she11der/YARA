rule SIGNATURE_BASE_Equationgroup_Curseroot_Win2K_V_2_1_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "bd2257ef-8170-547d-9c5e-7ff03404495c"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1324-L1340"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "64ea35c9287ed35b5e7fbc8aaa228f87bc003111dd6fc35f5277eeea5f371a2c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a1637948ed6ebbd2e582eb99df0c06b27a77c01ad1779b3d84c65953ca2cb603"

	strings:
		$s1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/%s,%s" fullword ascii
		$op0 = { c7 44 24 04 ff ff ff ff 89 04 24 e8 46 65 01 00 }
		$op1 = { 8d 5d 88 89 1c 24 e8 24 1b 01 00 be ff ff ff ff }
		$op2 = { d3 e0 48 e9 0c ff ff ff 8b 45 }

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and $s1 and 2 of ($op*))
}
