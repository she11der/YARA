rule SIGNATURE_BASE_PUA_VULN_Driver_Cpuid_Cpuzsys_Cpuidservice_7710 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - cpuz.sys"
		author = "Florian Roth"
		id = "9b4f6fc7-e597-5efd-9a85-6fd63fa9844b"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2384-L2407"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "771015b2620942919bb2e0683476635b7a09db55216d6fbf03534cb18513b20c"
		hash = "8d57e416ea4bb855b78a2ff3c80de1dfbb5dc5ee9bfbdddb23e46bd8619287e2"
		hash = "900dd68ccc72d73774a347b3290c4b6153ae496a81de722ebb043e2e99496f88"
		hash = "f74ffd6916333662900cbecb90aca2d6475a714ce410adf9c5c3264abbe5732c"
		logic_hash = "3c281f5381de85adcfba468cfced2fa0b400d90bb2a14494da37bd9b21e60e36"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004300500055004900440020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00430050005500490044 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e003100360033003800350020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0031002e0037003600300030002e00310036003300380035 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006300700075007a002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0043005000550049004400200073006500720076006900630065 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006300700075007a002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400280043002900200032003000310035002000430050005500490044 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
