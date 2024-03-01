rule SIGNATURE_BASE_PUA_VULN_Driver_Asustekcomputerinc_Eiosys_Asusvgakernelmodedriver_B175 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - EIO.sys"
		author = "Florian Roth"
		id = "1c0669aa-b156-580f-9bb0-d69502af6a7f"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2905-L2925"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b17507a3246020fa0052a172485d7b3567e0161747927f2edf27c40e310852e0"
		logic_hash = "bfcaa037bc06303a0de6a0372cd9dd49bd9801610989df46ca19fd844b22560e"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004100530055005300200056004700410020004b00650072006e0065006c0020004d006f006400650020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004100530055005300540065004b00200043006f006d0070007500740065007200200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e00390036 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e00390036 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00450049004f002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004100530055005300200056004700410020004b00650072006e0065006c0020004d006f006400650020004400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00450049004f002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000320030003000370020004100530055005300540065004b00200043006f006d0070007500740065007200200049006e0063002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}