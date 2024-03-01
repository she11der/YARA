rule SIGNATURE_BASE_PUA_VULN_Driver_Trendmicroinc_Tmcommsys_Aegis_C901 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - TmComm.sys"
		author = "Florian Roth"
		id = "a1c33a78-bef9-59fc-8976-876c1fe68aff"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L6150-L6170"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "c9014b03866bf37faa8fdb16b6af7cfec976aaef179fd5797d0c0bf8079d3a8c"
		logic_hash = "2320a0cc02aa28c6495f553b2c7c9c0486599e510d8378dfb3f15b988ff90983"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005400720065006e0064004d006900630072006f00200043006f006d006d006f006e0020004d006f00640075006c0065 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005400720065006e00640020004d006900630072006f00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0032002e0030002e0030002e0031003100310038 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0054006d0043006f006d006d002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00410045004700490053 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0054006d0043006f006d006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300035002d00320030003000370020005400720065006e00640020004d006900630072006f00200049006e0063006f00720070006f00720061007400650064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
