rule SIGNATURE_BASE_Equationgroup_Scripme : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file scripme"
		author = "Florian Roth (Nextron Systems)"
		id = "a2c5cd8b-c104-57d9-9ce2-a0b9a8dd9288"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L32-L48"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "5cffded6563bb3c94868f25e086be8d92837a7656707bf4e6a9e9f375d9ee7e0"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a1adf1c1caad96e7b7fd92cbf419c4cfa13214e66497c9e46ec274a487cd098a"

	strings:
		$x1 = "running \\\"tcpdump -n -n\\\", on the environment variable \\$INTERFACE, scripted" fullword ascii
		$x2 = "Cannot read $opetc/scripme.override -- are you root?" ascii
		$x3 = "$ENV{EXPLOIT_SCRIPME}" ascii
		$x4 = "$opetc/scripme.override" ascii

	condition:
		( filesize <30KB and 1 of them )
}
