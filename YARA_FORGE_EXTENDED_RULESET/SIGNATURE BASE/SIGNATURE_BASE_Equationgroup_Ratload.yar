rule SIGNATURE_BASE_Equationgroup_Ratload : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file ratload"
		author = "Florian Roth (Nextron Systems)"
		id = "81590569-e81b-5d97-8295-cc6f018fab98"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L734-L749"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "34298175663a01b26e317c31c720f2f4fe93a5c7e375c9642664479d8672e8cd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4a4a8f2f90529bee081ce2188131bac4e658a374a270007399f80af74c16f398"

	strings:
		$x1 = "/tmp/ratload.tmp.sh" fullword ascii
		$x2 = "Remote Usage: /bin/telnet locip locport < /dev/console | /bin/sh\"" fullword ascii
		$s6 = "uncompress -f ${NAME}.Z && PATH=. ${ARGS1} ${NAME} ${ARGS2} && rm -f ${NAME}" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
