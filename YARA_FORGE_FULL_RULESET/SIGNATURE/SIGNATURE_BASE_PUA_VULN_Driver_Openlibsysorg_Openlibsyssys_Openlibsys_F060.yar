rule SIGNATURE_BASE_PUA_VULN_Driver_Openlibsysorg_Openlibsyssys_Openlibsys_F060 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - OpenLibSys.sys"
		author = "Florian Roth"
		id = "b6ebdc92-1ca5-5f13-beef-d6adf037e732"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1714-L1734"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f0605dda1def240dc7e14efa73927d6c6d89988c01ea8647b671667b2b167008"
		logic_hash = "c73f19c87d63e9986e5f44a368f4b8305b7bff17ebdeb85f309751f54f76db48"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004f00700065006e004c00690062005300790073 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004f00700065006e004c00690062005300790073002e006f00720067 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0031002e0033 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0031002e0033 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004f00700065006e004c00690062005300790073002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004f00700065006e004c00690062005300790073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004f00700065006e004c00690062005300790073002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003000370020004f00700065006e004c00690062005300790073002e006f00720067 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
