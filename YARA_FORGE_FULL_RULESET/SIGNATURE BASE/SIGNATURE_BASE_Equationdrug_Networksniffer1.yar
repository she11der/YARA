rule SIGNATURE_BASE_Equationdrug_Networksniffer1
{
	meta:
		description = "EquationDrug - Backdoor driven by network sniffer - mstcp32.sys, fat32.sys"
		author = "Florian Roth (Nextron Systems)"
		id = "21a500e7-3011-50e6-b685-f4f65d6dee17"
		date = "2015-03-11"
		modified = "2023-01-06"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L368-L388"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "26e787997a338d8111d96c9a4c103cf8ff0201ce"
		logic_hash = "ec90cba3b790c52f475a08b586f5af5a88ec46cfcf8abd74435981a34dfdb3f7"
		score = 75
		quality = 35
		tags = ""

	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "\\Registry\\User\\CurrentUser\\" wide
		$s3 = "sys\\mstcp32.dbg" fullword ascii
		$s7 = "mstcp32.sys" fullword wide
		$s8 = "p32.sys" fullword ascii
		$s9 = "\\Device\\%ws_%ws" wide
		$s10 = "\\DosDevices\\%ws" wide
		$s11 = "\\Device\\%ws" wide

	condition:
		all of them
}
