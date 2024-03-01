rule SIGNATURE_BASE_Equationgroup_Watcher_Solaris_I386_V_3_3_0 : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "e75c6ed9-b6e6-530d-a6ac-40bd0477754f"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1240-L1256"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "61ded97e99e6bdfe2738c6d73719b3182d970aba8ea9d7cab751349669129de2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "395ec2531970950ffafde234dded0cce0c95f1f9a22763d1d04caa060a5222bb"

	strings:
		$s1 = "getexecname" fullword ascii
		$s2 = "invalid option `" fullword ascii
		$s6 = "__fpstart" ascii
		$s12 = "GHFIJKLMNOPQRSTUVXW" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <700KB and all of them )
}
