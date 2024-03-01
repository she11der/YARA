rule SIGNATURE_BASE_PUA_VULN_Driver_Trendmicroinc_Tmcommsys_Trendmicroeyes_BCFC : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - TmComm.sys"
		author = "Florian Roth"
		id = "aabd529a-516f-5e7f-85e2-b7fa207b89cd"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L4861-L4881"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "bcfc2c9883e6c1b8429be44cc4db988a9eecb544988fbd756d18cfca6201876f"
		logic_hash = "10b04a7ca71652632fb836bfb76f6be8b4c1d9e7e6566f623b52a850b3dbebde"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005400720065006e0064004d006900630072006f00200043006f006d006d006f006e0020004d006f00640075006c0065 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005400720065006e00640020004d006900630072006f00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0037002e00330030002e0030002e0031003000340039 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0037002e00330030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0054006d0043006f006d006d002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005400720065006e00640020004d006900630072006f00200045007900650073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0054006d0043006f006d006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000200028004300290020002000320030003100370020005400720065006e00640020004d006900630072006f00200049006e0063006f00720070006f00720061007400650064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
