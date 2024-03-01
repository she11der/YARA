import "pe"

rule SIGNATURE_BASE_EQGRP_Payload
{
	meta:
		description = "EQGRP Toolset Firewall - file payload.py"
		author = "Florian Roth (Nextron Systems)"
		id = "949cb68b-e384-578c-a906-a4d9234dc668"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L315-L329"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "22e2a4809f6646437ab0824238fec791f3760ac305f9c818089797b011425b3d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"

	strings:
		$s1 = "can't find target version module!" fullword ascii
		$s2 = "class Payload:" fullword ascii

	condition:
		all of them
}
