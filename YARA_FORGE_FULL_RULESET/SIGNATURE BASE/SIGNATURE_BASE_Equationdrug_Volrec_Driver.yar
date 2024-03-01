rule SIGNATURE_BASE_Equationdrug_Volrec_Driver
{
	meta:
		description = "EquationDrug - Collector plugin for Volrec - msrstd.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "db4f3f65-bdc4-565d-ad59-25a16ec7c9d2"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L456-L470"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ee2b504ad502dc3fed62d6483d93d9b1221cdd6c"
		logic_hash = "24b8202a8590ddb1dd76e01499d02282ad40a6fd6f6b9020040381a370e91f40"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "msrstd.sys" fullword wide
		$s1 = "msrstd.pdb" fullword ascii
		$s2 = "msrstd driver" fullword wide

	condition:
		all of them
}
