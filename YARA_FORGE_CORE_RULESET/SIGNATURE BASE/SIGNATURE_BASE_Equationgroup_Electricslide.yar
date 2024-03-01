rule SIGNATURE_BASE_Equationgroup_Electricslide : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file electricslide"
		author = "Florian Roth (Nextron Systems)"
		id = "5b1e5293-806a-58e6-b865-66025c8d8c32"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L310-L326"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0803b61afc592d4fba523dc54d8f856a557b916a9f6e256efccd50178e8e024c"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d27814b725568fa73641e86fa51850a17e54905c045b8b31a9a5b6d2bdc6f014"

	strings:
		$x1 = "Firing with the same hosts, on altername ports (target is on 8080, listener on 443)" fullword ascii
		$x2 = "Recieved Unknown Command Payload: 0x%x" fullword ascii
		$x3 = "Usage: eslide   [options] <-t profile> <-l listenerip> <targetip>" fullword ascii
		$x4 = "-------- Delete Key - Remove a *closed* tab" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <2000KB and 1 of them )
}
