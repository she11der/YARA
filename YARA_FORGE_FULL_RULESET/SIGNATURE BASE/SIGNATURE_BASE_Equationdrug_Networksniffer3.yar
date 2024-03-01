rule SIGNATURE_BASE_Equationdrug_Networksniffer3
{
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "c6b1658b-cbc6-535a-a3a2-15ce3cf6e4f6"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L439-L454"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "14599516381a9646cd978cf962c4f92386371040"
		logic_hash = "18c516fe0cd74e7a02ee15260abf3d27bba992492e6042a148abdee3086a9a00"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Corporation. All rights reserved." fullword wide
		$s1 = "IP Transport Driver" fullword wide
		$s2 = "tdip.sys" fullword wide
		$s3 = "tdip.pdb" fullword ascii

	condition:
		all of them
}
