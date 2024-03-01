rule SIGNATURE_BASE_Equationgroup__Magicjack_V1_1_0_0_Client : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- from files magicjack_v1.1.0.0_client-1.1.0.0.py"
		author = "Florian Roth (Nextron Systems)"
		id = "be18f36c-3d6c-53a3-89b6-bfc53e1dd87d"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L971-L988"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "5e22b01aa9b1283fa7a326b7c0f8047ed373fac750c89e9ba02c49f0f454e275"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "63292a2353275a3bae012717bb500d5169cd024064a1ce8355ecb4e9bfcdfdd1"

	strings:
		$s1 = "temp = ((left >> 1) ^ right) & 0x55555555" fullword ascii
		$s2 = "right ^= (temp <<  16) & 0xffffffff" fullword ascii
		$s3 = "tempresult = \"\"" fullword ascii
		$s4 = "num = self.bytes2long(data)" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <80KB and 3 of them ) or ( all of them )
}
