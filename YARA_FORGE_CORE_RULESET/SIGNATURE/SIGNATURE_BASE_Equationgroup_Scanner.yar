rule SIGNATURE_BASE_Equationgroup_Scanner : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file scanner"
		author = "Florian Roth (Nextron Systems)"
		id = "b2f9c534-0ca7-5223-b85e-8e74c3cfa6ff"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L834-L849"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "b0454fd41d3591fc5811da6407a422b7c28d0b923109cdfa85b337cc7fffb178"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "dcbcd8a98ec93a4e877507058aa26f0c865b35b46b8e6de809ed2c4b3db7e222"

	strings:
		$x1 = "program version netid     address             service         owner" fullword ascii
		$x4 = "*** Sorry about the raw output, I'll leave it for now" fullword ascii
		$x5 = "-scan winn %s one" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
