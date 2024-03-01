rule SIGNATURE_BASE_Equationgroup_DUL : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file DUL"
		author = "Florian Roth (Nextron Systems)"
		id = "6dd90b30-30cb-531c-b8e2-fc208b21e8e6"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L539-L553"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "55df9a844352babf0c30075139e2a62cbf9db898280546d27b172e4d611ce1c0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "24d1d50960d4ebf348b48b4db4a15e50f328ab2c0e24db805b106d527fc5fe8e"

	strings:
		$x1 = "?Usage: %s <shellcode> <output_file>" fullword ascii
		$x2 = "Here is the decoder+(encoded-decoder)+payload" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <80KB and 1 of them ) or ( all of them )
}
