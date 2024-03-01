rule SIGNATURE_BASE_PUA_VULN_Driver_Oti_Otipcibussys_Kernelmodedrivertoaccessphysicalmemoryandports_4E3E : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - otipcibus.sys"
		author = "Florian Roth"
		id = "71052609-e8a3-5611-ad92-8cf43a0fddf0"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3571-L3590"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4e3eb5b9bce2fd9f6878ae36288211f0997f6149aa8c290ed91228ba4cdfae80"
		logic_hash = "ef5cb96dc4f6eaaf24fe9d0a65ccb5efe54cb672a9328b9dc2bbc36af82d96e2"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0048006100720064007700610072006500200041006300630065007300730020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004f00540069 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0031003000300030002e0030002e0031 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0031003000300030002e0030002e0031 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006f0074006900700063006900620075007300360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004b00650072006e0065006c0020004d006f00640065002000440072006900760065007200200054006f002000410063006300650073007300200050006800790073006900630061006c0020004d0065006d006f0072007900200041006e006400200050006f007200740073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006f0074006900700063006900620075007300360034002e007300790073 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
