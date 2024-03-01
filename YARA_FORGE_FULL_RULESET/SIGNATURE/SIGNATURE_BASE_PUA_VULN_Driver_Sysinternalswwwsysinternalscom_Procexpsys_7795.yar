rule SIGNATURE_BASE_PUA_VULN_Driver_Sysinternalswwwsysinternalscom_Procexpsys_7795 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - procexp.Sys"
		author = "Florian Roth"
		id = "84866b07-19cc-5c75-acc3-7640adcf68e8"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L5440-L5460"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "77950e2a40ac0447ae7ee1ee3ef1242ce22796a157074e6f04e345b1956e143c"
		logic_hash = "f59507fdf64c5eca6139f149595b9919704fead73d4e66c93630ca6cf9582a82"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0020002000200020002000200020002000200020002000200020002000200020 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0053007900730069006e007400650072006e0061006c00730020002d0020007700770077002e0073007900730069006e007400650072006e0061006c0073002e0063006f006d }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00310035002e00300030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00310035002e00300030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00700072006f0063006500780070002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0020002000200020002000200020002000200020002000200020002000200020 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00700072006f0063006500780070002e005300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400200028004300290020004d00610072006b002000520075007300730069006e006f007600690063006800200031003900390036002d0032003000310034 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}