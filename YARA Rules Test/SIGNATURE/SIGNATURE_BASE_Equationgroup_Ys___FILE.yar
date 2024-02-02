rule SIGNATURE_BASE_Equationgroup_Ys___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ys.auto"
		author = "Florian Roth (Nextron Systems)"
		id = "abd120e7-23f8-530e-b21e-c50a2b571332"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L751-L766"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "4962cc732ce3dea6dc52c7d91ce94089eb4498ba4c442ecc6363ea75de47de31"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a6387307d64778f8d9cfc60382fdcf0627cde886e952b8d73cc61755ed9fde15"

	strings:
		$x1 = "EXPLOIT_SCRIPME=\"$EXPLOIT_SCRIPME\"" fullword ascii
		$x3 = "DEFTARGET=`head /current/etc/opscript.txt 2>/dev/null | grepip 2>/dev/null | head -1`" fullword ascii
		$x4 = "FATAL ERROR: -x port and -n port MUST NOT BE THE SAME." fullword ascii

	condition:
		filesize <250KB and 1 of them
}