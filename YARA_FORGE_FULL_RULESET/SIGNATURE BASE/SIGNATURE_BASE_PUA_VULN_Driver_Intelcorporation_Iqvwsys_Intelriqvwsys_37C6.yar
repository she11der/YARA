rule SIGNATURE_BASE_PUA_VULN_Driver_Intelcorporation_Iqvwsys_Intelriqvwsys_37C6 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - iQVW64.SYS"
		author = "Florian Roth"
		id = "f4b17a75-3160-5a73-afe6-531c41fae197"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L6356-L6376"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "37c637a74bf20d7630281581a8fae124200920df11ad7cd68c14c26cc12c5ec9"
		logic_hash = "7ab6c3fe4c9cd61c171a71d631a8efc34121bac85e1abf5f281b150f4b6a77a5"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0049006e00740065006c0028005200290020004e006500740077006f0072006b0020004100640061007000740065007200200044006900610067006e006f00730074006900630020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0049006e00740065006c00200043006f00720070006f0072006100740069006f006e0020 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0033002e0032002e003100370020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0033002e0032002e00310037 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006900510056005700360034002e005300590053 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0049006e00740065006c0028005200290020006900510056005700360034002e005300590053 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006900510056005700360034002e005300590053 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300032002d003200300031003800200049006e00740065006c00200043006f00720070006f0072006100740069006f006e00200041006c006c0020005200690067006800740073002000520065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}