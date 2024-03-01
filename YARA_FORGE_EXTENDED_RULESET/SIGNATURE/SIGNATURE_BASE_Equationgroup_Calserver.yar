rule SIGNATURE_BASE_Equationgroup_Calserver : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file calserver"
		author = "Florian Roth (Nextron Systems)"
		id = "abe935ee-8579-54f0-b6d3-172d6e2c0482"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L276-L291"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "85080074058703a696ac7f978abd8f4d5234f6553c19736fb52375421c4af42b"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "048625e9a0ca46d7fe221e262c8dd05e7a5339990ffae2fb65a9b0d705ad6099"

	strings:
		$x1 = "usage: %s <host> <port> e <contents of a local file to be executed on target>" fullword ascii
		$x2 = "Writing your %s to target." fullword ascii
		$x3 = "(e)xploit, (r)ead, (m)ove and then write, (w)rite" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 1 of them )
}
