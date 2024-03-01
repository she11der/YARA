rule SIGNATURE_BASE_Equationgroup_Sshobo : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file sshobo"
		author = "Florian Roth (Nextron Systems)"
		id = "b9392aec-34a8-5ad2-b3fd-eea907d19701"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L207-L223"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "90c892e06ccedb6a3208d728e9f3c27c14bbe1b4c13b63d4a350bbbf38efbe9d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c7491898a0a77981c44847eb00fb0b186aa79a219a35ebbca944d627eefa7d45"

	strings:
		$x1 = "Requested forwarding of port %d but user is not root." fullword ascii
		$x2 = "internal error: we do not read, but chan_read_failed for istate" fullword ascii
		$x3 = "~#  - list forwarded connections" fullword ascii
		$x4 = "packet_inject_ignore: block" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <600KB and all of them )
}
