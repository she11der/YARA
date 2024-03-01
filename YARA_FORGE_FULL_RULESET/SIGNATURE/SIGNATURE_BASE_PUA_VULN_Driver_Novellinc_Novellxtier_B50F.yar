rule SIGNATURE_BASE_PUA_VULN_Driver_Novellinc_Novellxtier_B50F : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - libnicm.sys"
		author = "Florian Roth"
		id = "fc6032d2-ef08-5fdb-be73-39dd42185b13"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L332-L352"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b50ffc60eaa4fb7429fdbb67c0aba0c7085f5129564d0a113fec231c5f8ff62e"
		hash = "b37b3c6877b70289c0f43aeb71349f7344b06063996e6347c3c18d8c5de77f3b"
		logic_hash = "662af5d505b5fee483356c1b5bcf2767c594bd690d5367a7b9f7ac9bea6b3c9d"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004e006f00760065006c006c0020005800540043004f004d0020005300650072007600690063006500730020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004e006f00760065006c006c002c00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0033002e0031002e0036002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0033002e0031002e0036 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004e006f00760065006c006c002000580054006900650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006c00690062006e00690063006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00280043002900200043006f007000790072006900670068007400200032003000300030002d0032003000300038002c0020004e006f00760065006c006c002c00200049006e0063002e00200041006c006c0020005200690067006800740073002000520065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
