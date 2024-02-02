rule SIGNATURE_BASE_Equationgroup_Magicjack_V1_1_0_0_Client_1_1_0_0___FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file magicjack_v1.1.0.0_client-1.1.0.0.py"
		author = "Florian Roth (Nextron Systems)"
		id = "008cb5cf-1d2d-5312-9474-2f93db190974"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L225-L239"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "44e853b8d148f84107d29449aa44b2e52226c9d2f397c019aa0f1d347863e388"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"

	strings:
		$x1 = "result = self.send_command(\"ls -al %s\" % self.options.DIR)" fullword ascii
		$x2 = "cmd += \"D=-l%s \" % self.options.LISTEN_PORT" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <80KB and 1 of them )
}