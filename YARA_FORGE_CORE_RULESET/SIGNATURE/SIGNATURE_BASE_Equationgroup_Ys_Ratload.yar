rule SIGNATURE_BASE_Equationgroup_Ys_Ratload : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ys.ratload.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "abd120e7-23f8-530e-b21e-c50a2b571332"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L136-L151"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "82d00b7eecdb60911ecd933387eeb2ce4eec9721993beee60247d1273ad3368f"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a340e5b5cfd41076bd4d6ad89d7157eeac264db97a9dddaae15d935937f10d75"

	strings:
		$x1 = "echo \"example: ${0} -l 192.168.1.1 -p 22222 -x 9999\"" fullword ascii
		$x2 = "-x [ port to start mini X server on DEFAULT = 12121 ]\"" fullword ascii
		$x3 = "CALLBACK_PORT=32177" fullword ascii

	condition:
		( uint16(0)==0x2123 and filesize <3KB and 1 of them )
}
