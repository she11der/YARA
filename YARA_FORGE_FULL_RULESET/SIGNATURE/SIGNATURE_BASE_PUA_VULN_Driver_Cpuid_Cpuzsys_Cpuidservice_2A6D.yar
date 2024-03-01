rule SIGNATURE_BASE_PUA_VULN_Driver_Cpuid_Cpuzsys_Cpuidservice_2A6D : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - cpuz.sys"
		author = "Florian Roth"
		id = "85b7f3f1-6324-543f-8855-8cb13096b367"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L980-L1002"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "2a6db9facf9e13d35c37dd468be04bae5f70c6127a9aee76daebddbdec95d486"
		hash = "1e16a01ef44e4c56e87abfbe03b2989b0391b172c3ec162783ad640be65ab961"
		hash = "aebcbfca180e372a048b682a4859fd520c98b5b63f6e3a627c626cb35adc0399"
		logic_hash = "81287d89ca576746e6a896bd07fbe5170da2360d614164940621d709c439ca8e"
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
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400280043002900200032003000310032002000430050005500490044 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}