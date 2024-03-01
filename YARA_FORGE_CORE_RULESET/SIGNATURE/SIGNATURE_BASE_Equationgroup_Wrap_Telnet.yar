rule SIGNATURE_BASE_Equationgroup_Wrap_Telnet : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file wrap-telnet.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "158e6ebc-6b43-5e94-9052-31408d848875"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L345-L360"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "aa7fda8b95b697bb0541642677579f9db9df379048421481cdb66068032bf681"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4962b307a42ba18e987d82aa61eba15491898978d0e2f0e4beb02371bf0fd5b4"

	strings:
		$s1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -s 22223 -x 9999\"" fullword ascii
		$s2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
		$s3 = "echo \"Call back port2 = ${SPORT}\"" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <4KB and 1 of them )
}
