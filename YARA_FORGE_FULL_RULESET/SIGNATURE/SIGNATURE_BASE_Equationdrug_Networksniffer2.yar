rule SIGNATURE_BASE_Equationdrug_Networksniffer2
{
	meta:
		description = "EquationDrug - Network Sniffer - tdip.sys"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		id = "afc5ae23-4965-5796-af3b-9e2705aea455"
		date = "2015-03-11"
		modified = "2023-12-05"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L418-L437"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7e3cd36875c0e5ccb076eb74855d627ae8d4627f"
		logic_hash = "d29744a801194e5488795a8167965b94290be477efe478ee3e71c4bc98733967"
		score = 75
		quality = 35
		tags = ""

	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "IP Transport Driver" fullword wide
		$s2 = "tdip.sys" fullword wide
		$s3 = "sys\\tdip.dbg" fullword ascii
		$s4 = "dip.sys" fullword ascii
		$s5 = "\\Device\\%ws_%ws" wide
		$s6 = "\\DosDevices\\%ws" wide
		$s7 = "\\Device\\%ws" wide

	condition:
		all of them
}
