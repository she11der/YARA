rule SIGNATURE_BASE_PUA_VULN_Driver_Dell_Dbutil_71FE : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - DBUtilDrv2.sys"
		author = "Florian Roth"
		id = "172e8e13-e1ff-5caf-9759-d607ef072215"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1903-L1920"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "71fe5af0f1564dc187eea8d59c0fbc897712afa07d18316d2080330ba17cf009"
		logic_hash = "dad7c23d78176f31a2a324998e3170a5096a50389ff83af590503fac69791890"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00440042005500740069006c }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00440065006c006c }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e0037002e0030002e0030 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00440042005500740069006c }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a900200032003000320031002000440065006c006c00200049006e0063002e00200041006c006c0020005200690067006800740073002000520065007300650072007600650064002e0020 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
