rule SIGNATURE_BASE_PUA_VULN_Driver_Lenovogrouplimitedr_Lenovodiagnosticsdriversys_Lenovodiagnostics_F05B : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - LenovoDiagnosticsDriver.sys"
		author = "Florian Roth"
		id = "791da32a-272c-5bde-9722-cc4c68321ad7"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1880-L1900"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe"
		logic_hash = "22098d721c4814786834b3ea781283f53d195ba35f51fc8fd75b45f7781d39d4"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004c0065006e006f0076006f00200044006900610067006e006f00730074006900630073002000440072006900760065007200200066006f0072002000570069006e0064006f0077007300200031003000200061006e00640020006c0061007400650072002e }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004c0065006e006f0076006f002000470072006f007500700020004c0069006d00690074006500640020002800520029 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0034002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0034002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004c0065006e006f0076006f0044006900610067006e006f00730074006900630073004400720069007600650072002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004c0065006e006f0076006f00200044006900610067006e006f00730074006900630073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004c0065006e006f0076006f0044006900610067006e006f00730074006900630073004400720069007600650072002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a9002000320030003200310020004c0065006e006f0076006f002000470072006f007500700020004c0069006d0069007400650064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}