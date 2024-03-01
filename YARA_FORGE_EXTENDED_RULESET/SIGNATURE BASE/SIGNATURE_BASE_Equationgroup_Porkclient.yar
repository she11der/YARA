rule SIGNATURE_BASE_Equationgroup_Porkclient : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file porkclient"
		author = "Florian Roth (Nextron Systems)"
		id = "5b34d5f9-bc76-5cc7-92f7-32c2b7ef7bcf"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L293-L308"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4de13f1cac8698fc86e44d29143877924aec4e6712415ee6b35810afed8072d6"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5c14e3bcbf230a1d7e2909876b045e34b1486c8df3c85fb582d9c93ad7c57748"

	strings:
		$s1 = "-c COMMAND: shell command string" fullword ascii
		$s2 = "Cannot combine shell command mode with args to do socket reuse" fullword ascii
		$s3 = "-r: Reuse socket for Nopen connection (requires -t, -d, -f, -n, NO -c)" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <30KB and 1 of them )
}
