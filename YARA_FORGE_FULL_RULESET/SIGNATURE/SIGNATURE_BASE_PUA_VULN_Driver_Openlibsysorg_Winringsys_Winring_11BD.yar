rule SIGNATURE_BASE_PUA_VULN_Driver_Openlibsysorg_Winringsys_Winring_11BD : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - WinRing0x64.sys"
		author = "Florian Roth"
		id = "370f3fc6-6199-5c19-a0b5-8c02fb89f30a"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L355-L376"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5"
		hash = "a7b000abbcc344444a9b00cfade7aa22ab92ce0cadec196c30eb1851ae4fa062"
		logic_hash = "e5777a3a1e71f287c18434a48c2990abd3e202c919378a9473541abe2b8f0ba5"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00570069006e00520069006e00670030 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004f00700065006e004c00690062005300790073002e006f00720067 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0032002e0030002e0035 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0032002e0030002e0035 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00570069006e00520069006e00670030002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00570069006e00520069006e00670030 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00570069006e00520069006e00670030002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300037002d00320030003000380020004f00700065006e004c00690062005300790073002e006f00720067002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
