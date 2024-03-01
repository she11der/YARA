rule SIGNATURE_BASE_PUA_VULN_Driver_Windowsrwinddkprovider_Cupfixerxsys_Windowsrwinddkdriver_8C74 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - CupFixerx64.sys"
		author = "Florian Roth"
		id = "32559d4c-eef4-5b67-a74c-f89589bc446b"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2882-L2902"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8c748ae5dcc10614cc134064c99367d28f3131d1f1dda0c9c29e99279dc1bdd9"
		logic_hash = "d0eb0738da64ce1a94278a422e829f01d1514ac4536fc2187aa5f4112b70f6e0"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00530069006e0063006500790020004300750070002000460069007800650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00570069006e0064006f007700730020002800520029002000570069006e00200037002000440044004b002000700072006f00760069006400650072 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00330032002e0030002e00310030003000310031002e00310033003300330037 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00330032002e0030002e00310030003000310031002e00310033003300330037 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00430075007000460069007800650072007800360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00570069006e0064006f007700730020002800520029002000570069006e00200037002000440044004b0020006400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00430075007000460069007800650072007800360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a90020004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
