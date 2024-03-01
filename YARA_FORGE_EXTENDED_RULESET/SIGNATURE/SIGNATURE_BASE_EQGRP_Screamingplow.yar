import "pe"

rule SIGNATURE_BASE_EQGRP_Screamingplow
{
	meta:
		description = "EQGRP Toolset Firewall - file screamingplow.sh"
		author = "Florian Roth (Nextron Systems)"
		id = "cb535ef0-e3ea-54cc-9082-3d63cc96d93a"
		date = "2016-08-16"
		modified = "2023-12-05"
		reference = "Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp.yar#L268-L282"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "429ff81b6079785cc45d81b5ebf8bccd49f30484ca692017b0b66484463606d4"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c7f4104c4607a03a1d27c832e1ebfc6ab252a27a1709015b5f1617b534f0090a"

	strings:
		$s1 = "What is the name of your PBD:" fullword ascii
		$s2 = "You are now ready for a ScreamPlow" fullword ascii

	condition:
		1 of them
}
