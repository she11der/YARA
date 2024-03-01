rule SIGNATURE_BASE_Equationgroup_Watcher_Linux_I386_V_3_3_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "3c5dc02b-a11a-5c61-8069-641ba90668ec"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1364-L1381"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "245662b561178f4d929ed858811846b2a49dc80af25396864a3d7bd90d16ac2b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ce4c9bfa25b8aad8ea68cc275187a894dec5d79e8c0b2f2f3ec4184dc5f402b8"

	strings:
		$s1 = "invalid option `" fullword ascii
		$s8 = "readdir64" fullword ascii
		$s9 = "89:z89:%r%opw" fullword wide
		$s13 = "Ropopoprstuvwypypop" fullword wide
		$s17 = "Missing argument for `-x'." fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <700KB and all of them )
}
