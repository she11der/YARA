rule SIGNATURE_BASE_PUA_VULN_Driver_Dtresearchinc_Iomemsys_Iomemsys_3D23 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - iomem64.sys"
		author = "Florian Roth"
		id = "b29e4411-a408-5bd5-a763-73c18b85e2b2"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3297-L3317"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "3d23bdbaf9905259d858df5bf991eb23d2dc9f4ecda7f9f77839691acef1b8c4"
		logic_hash = "4f494f3f2367bbc5751a09b79775ea61f62986b82375c8c98bf6a77203174be1"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0044005400520020004b00650072006e0065006c0020006d006f006400650020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00440054002000520065007300650061007200630068002c00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0032002e0033002e0030002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e0033002e0030002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0069006f006d0065006d002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0069006f006d0065006d002e007300790073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0069006f006d0065006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0044005400200052006500730065006100720063006800200049006e0063002e00200041006c006c0020005200690067006800740073002000520065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
