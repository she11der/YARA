rule SIGNATURE_BASE_PUA_VULN_Driver_Elaboratebytesag_Elbycdio_Cdrtools_ADA4 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - ElbyCDIO.sys"
		author = "Florian Roth"
		id = "55ef1733-e9e8-5c60-8461-233e4fa4f0ae"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L4672-L4692"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "ada4e42bf5ef58ef1aad94435441003b1cc1fcaa5d38bfdbe1a3d736dc451d47"
		logic_hash = "d102d9add684a93cec7f05196b3e3ca39ff470df7df1b5fd58001b460c0a2dfc"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0045006c0062007900430044002000570069006e0064006f007700730020004e0054002f0032003000300030002f0058005000200049002f004f0020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0045006c00610062006f0072006100740065002000420079007400650073002000410047 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002c00200030002c00200031002c00200032 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002c00200030002c00200030002c00200030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0045006c00620079004300440049004f }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0043004400520054006f006f006c0073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0045006c00620079004300440049004f002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003000300020002d0020003200300030003800200045006c00610062006f0072006100740065002000420079007400650073002000410047 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
