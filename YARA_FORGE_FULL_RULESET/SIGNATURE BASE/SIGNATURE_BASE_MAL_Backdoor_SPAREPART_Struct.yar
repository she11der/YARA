rule SIGNATURE_BASE_MAL_Backdoor_SPAREPART_Struct : FILE
{
	meta:
		description = "Detects the PDB and a struct used in SPAREPART"
		author = "Mandiant"
		id = "a04296d5-c146-5142-a8e8-418651f6b755"
		date = "2022-12-14"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/mal_ru_sparepart_dec22.yar#L22-L39"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f9cd5b145e372553dded92628db038d8"
		logic_hash = "807c7404146c08995440987aef78ecde11224f7d6cad1a0d22269b2bf46a44e5"
		score = 50
		quality = 85
		tags = "FILE"
		disclaimer = "This rule is meant for hunting and is not tested to run in a production environment."

	strings:
		$pdb = "c:\\Users\\user\\Desktop\\ImageAgent\\ImageAgent\\PreAgent\\src\\builder\\agent.pdb" ascii nocase
		$struct = { 44 89 ac ?? ?? ?? ?? ?? 4? 8b ac ?? ?? ?? ?? ?? 4? 83 c5 28 89 84 ?? ?? ?? ?? ?? 89 8c ?? ?? ?? ?? ?? 89 54 ?? ?? 44 89 44 ?? ?? 44 89 4c ?? ?? 44 89 54 ?? ?? 44 89 5c ?? ?? 89 5c ?? ?? 89 7c ?? ?? 89 74 ?? ?? 89 6c ?? ?? 44 89 74 ?? ?? 44 89 7c ?? ?? 44 89 64 ?? ?? 8b 84 ?? ?? ?? ?? ?? 44 8b c8 8b 84 ?? ?? ?? ?? ?? 44 8b c0 4? 8d 15 ?? ?? ?? ?? 4? 8b cd ff 15 ?? ?? ?? ??  }

	condition:
		( uint16(0)==0x5A4D) and uint32( uint32(0x3C))==0x00004550 and $pdb and $struct and filesize <20KB
}
