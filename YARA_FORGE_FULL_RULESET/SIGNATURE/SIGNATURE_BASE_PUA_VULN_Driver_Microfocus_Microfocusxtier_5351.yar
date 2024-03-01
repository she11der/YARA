rule SIGNATURE_BASE_PUA_VULN_Driver_Microfocus_Microfocusxtier_5351 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - nscm.sys"
		author = "Florian Roth"
		id = "e2d580c9-79e6-53f1-ab4a-77e2715b6f91"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3931-L3950"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5351c81b4ec5a0d79c39d24bac7600d10eac30c13546fde43d23636b3f421e7c"
		logic_hash = "efbf3fd36c3ca5c2b95796cdaefb175ad1957866649e73366a1d6810cbcb5e81"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0058005400690065007200200053006500630075007200690074007900200043006f006e00740065007800740020004d0061006e0061006700650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f00200046006f006300750073 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0033002e0031002e00310032002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0033002e0031002e00310032 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d006900630072006f00200046006f006300750073002000580054006900650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006e00730063006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00280043002900200043006f007000790072006900670068007400200032003000300030002d0032003000310037002c0020004d006900630072006f00200046006f006300750073002e00200041006c006c0020005200690067006800740073002000520065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
