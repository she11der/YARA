rule SIGNATURE_BASE_PUA_VULN_Driver_Zemanaltd_Zam_8FE9 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - zam64.sys"
		author = "Florian Roth"
		id = "45ac5fe9-25e2-5ee9-a410-95d19ec75e33"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1121-L1138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8fe9828bea83adc8b1429394db7a556a17f79846ad0bfb7f242084a5c96edf2a"
		logic_hash = "f293cb0a8bbc710428a7a4ae582f9d6ed60954afeb84efe8b74da38ff41732c1"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005a0041004d }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005a0065006d0061006e00610020004c00740064002e }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e00310037002e003100310035 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005a0041004d }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]005a0065006d0061006e00610020004c00740064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
