rule SIGNATURE_BASE_PUA_VULN_Driver_Elaboratebytesag_Elbycdio_Cdrtools_EEA5 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - elbycdio.sys"
		author = "Florian Roth"
		id = "2942b5b0-7270-5b7a-98f7-beee11e7aa57"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L4488-L4508"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "eea53103e7a5a55dc1df79797395a2a3e96123ebd71cdd2db4b1be80e7b3f02b"
		logic_hash = "47bcbc01fc9d12d72613093da34efd44b9d45af700a83450e36aed9fa972ae9b"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0045006c0062007900430044002000570069006e0064006f007700730020004e0054002f0032003000300030002f0058005000200049002f004f0020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0045006c00610062006f0072006100740065002000420079007400650073002000410047 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002c00200030002c00200032002c00200030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002c00200030002c00200030002c00200030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0045006c00620079004300440049004f }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0043004400520054006f006f006c0073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0045006c00620079004300440049004f002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003000300020002d0020003200300030003900200045006c00610062006f0072006100740065002000420079007400650073002000410047 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
