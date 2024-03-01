rule SIGNATURE_BASE_Equationdrug_Networksniffer5
{
	meta:
		description = "EquationDrug - Network-sniffer/patcher - atmdkdrv.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "9eac2c51-3ad7-5346-a985-39733bc204c2"
		date = "2015-03-11"
		modified = "2023-01-06"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L556-L574"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "09399b9bd600d4516db37307a457bc55eedcbd17"
		logic_hash = "84f009e2ef639e5270273a7d9dd2542fdf1386c4c8363071d711e2333a112cd1"
		score = 75
		quality = 60
		tags = ""

	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "\\Registry\\User\\CurrentUser\\" wide
		$s2 = "atmdkdrv.sys" fullword wide
		$s4 = "\\Device\\%ws_%ws" wide
		$s5 = "\\DosDevices\\%ws" wide
		$s6 = "\\Device\\%ws" wide

	condition:
		all of them
}
