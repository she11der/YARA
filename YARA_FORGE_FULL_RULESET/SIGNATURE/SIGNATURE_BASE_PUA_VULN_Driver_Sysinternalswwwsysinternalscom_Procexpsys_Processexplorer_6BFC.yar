rule SIGNATURE_BASE_PUA_VULN_Driver_Sysinternalswwwsysinternalscom_Procexpsys_Processexplorer_6BFC : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - procexp.Sys"
		author = "Florian Roth"
		id = "c5104fcb-7d6a-54dc-a79e-366f16ecd8a0"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2621-L2643"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6bfc0f425de9f4e7480aa2d1f2e08892d0553ed0df1c31e9bf3d8d702f38fa2e"
		hash = "3c7e5b25a33a7805c999d318a9523fcae46695a89f55bbdb8bb9087360323dfc"
		hash = "46621554728bc55438c7c241137af401250f062edef6e7efecf1a6f0f6d0c1f7"
		logic_hash = "bc754dc4c4a916691f3d32e8cfad99f1a426d9d6d59d9d6f3c93cabfd581d8a9"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00500072006f00630065007300730020004500780070006c006f007200650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0053007900730069006e007400650072006e0061006c00730020002d0020007700770077002e0073007900730069006e007400650072006e0061006c0073002e0063006f006d }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00310035002e00300030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00310035002e00300030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00700072006f0063006500780070002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00500072006f00630065007300730020004500780070006c006f007200650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00700072006f0063006500780070002e005300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400200028004300290020004d002e002000520075007300730069006e006f007600690063006800200031003900390036002d0032003000310031 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}