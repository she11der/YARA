rule SIGNATURE_BASE_Equationgroup_Gr_Dev_Bin_Post : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1274-L1287"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "ffd95302df11d1ebab37817e967a1ad4d1e85e62b38a0ccd6adf0f36925e64c1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c1546155efa95dbc4e3cc95299a3968fc075f89d33164e78b00b76c7d08a0591"

	strings:
		$x1 = "op=cron&action=once&frame=cronOnceFrame&cronK=cronV&cronCommand=%2Ftmp%2Ftmpwatch&time=12%3A12+01%2F28%2F2005" ascii

	condition:
		( filesize <1KB and all of them )
}
