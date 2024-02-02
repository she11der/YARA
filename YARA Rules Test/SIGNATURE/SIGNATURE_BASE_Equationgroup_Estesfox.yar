rule SIGNATURE_BASE_Equationgroup_Estesfox
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file estesfox"
		author = "Florian Roth (Nextron Systems)"
		id = "f2e8b8ba-af09-5e7c-a99c-4f620a0917c9"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L801-L814"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "bfbc8ac62dcb61b492b1803de535f51ceb54ac83e45071270a6ef5faeaa521b2"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "33530cae130ee9d9deeee60df9292c00242c0fe6f7b8eedef8ed09881b7e1d5a"

	strings:
		$x1 = "chown root:root x;chmod 4777 x`' /tmp/logwatch.$2/cron" fullword ascii

	condition:
		all of them
}