rule SIGNATURE_BASE_PUA_VULN_Driver_Zemanaltd_Zam_DE8F : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - zam64.sys"
		author = "Florian Roth"
		id = "245da08c-d629-53cb-83fb-476f4fdd1512"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L6446-L6463"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "de8f8006d8ee429b5f333503defa54b25447f4ed6aeade5e4219e23f3473ef1c"
		logic_hash = "0cb5b26dd0cd26c77df642ea6bfffdcede293cdb1ecc15430241ab538f835162"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005a0041004d }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005a0065006d0061006e00610020004c00740064002e }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e00320030002e003100300034 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005a0041004d }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]005a0065006d0061006e00610020004c00740064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
