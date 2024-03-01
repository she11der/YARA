rule SIGNATURE_BASE_Equationdrug_Filesystem_Filter
{
	meta:
		description = "EquationDrug - Filesystem filter driver - volrec.sys, scsi2mgr.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "7077daf6-3d51-5ff2-bc74-95cb169a7cd2"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L576-L590"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "57fa4a1abbf39f4899ea76543ebd3688dcc11e13"
		logic_hash = "5da0c279da1b84a41e7d15df3c19cd50af1872156f133de0a367b9140425aa11"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "volrec.sys" fullword wide
		$s1 = "volrec.pdb" fullword ascii
		$s2 = "Volume recognizer driver" fullword wide

	condition:
		all of them
}
