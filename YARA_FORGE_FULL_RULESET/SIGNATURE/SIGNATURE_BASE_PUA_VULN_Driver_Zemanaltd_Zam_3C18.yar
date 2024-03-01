rule SIGNATURE_BASE_PUA_VULN_Driver_Zemanaltd_Zam_3C18 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - zam64.sys"
		author = "Florian Roth"
		id = "94b7a58c-0092-5d81-985f-330599efe25a"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3254-L3271"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3c18ae965fba56d09a65770b4d8da54ccd7801f979d3ebd283397bc99646004b"
		logic_hash = "4f958ccb21b5cbd28c25a9c2e1a08fcf00e24bfa9e7814b9e68b87814dd04f4c"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005a0041004d }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005a0065006d0061006e00610020004c00740064002e }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e00310036002e003900320038 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005a0041004d }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]005a0065006d0061006e00610020004c00740064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
