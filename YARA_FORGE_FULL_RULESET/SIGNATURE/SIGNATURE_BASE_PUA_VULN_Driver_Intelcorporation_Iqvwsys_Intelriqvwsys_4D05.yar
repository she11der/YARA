rule SIGNATURE_BASE_PUA_VULN_Driver_Intelcorporation_Iqvwsys_Intelriqvwsys_4D05 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - iQVW64.SYS"
		author = "Florian Roth"
		id = "e52c22aa-347f-5618-93b8-b4dab3f04b35"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2689-L2716"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4d0580c20c1ba74cf90d44c82d040f0039542eea96e4bbff3996e6760f457cee"
		hash = "77c5e95b872b1d815d6d3ed28b399ca39f3427eeb0143f49982120ff732285a9"
		hash = "cff9aa9046bdfd781d34f607d901a431a51bb7e5f48f4f681cc743b2cdedc98c"
		hash = "b51ddcf8309c80384986dda9b11bf7856b030e3e885b0856efdb9e84064917e5"
		hash = "ff115cefe624b6ca0b3878a86f6f8b352d1915b65fbbdc33ae15530a96ebdaa7"
		hash = "a566af57d88f37fa033e64b1d8abbd3ffdacaba260475fbbc8dab846a824eff5"
		hash = "57a389da784269bb2cc0a258500f6dfbf4f6269276e1192619ce439ec77f4572"
		hash = "d74755311d127d0eb7454e56babc2db8dbaa814bc4ba8e2a7754d3e0224778e1"
		logic_hash = "4e043c30e6b74d21ef14aec63454c6a48c0ac3e770b39114dc6ba988023ebabf"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0049006e00740065006c0028005200290020004e006500740077006f0072006b0020004100640061007000740065007200200044006900610067006e006f00730074006900630020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0049006e00740065006c00200043006f00720070006f0072006100740069006f006e0020 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e00300033002e0030002e00340020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e00300033002e0030002e0034 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006900510056005700360034002e005300590053 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0049006e00740065006c0028005200290020006900510056005700360034002e005300590053 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006900510056005700360034002e005300590053 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300032002d003200300030003600200049006e00740065006c00200043006f00720070006f0072006100740069006f006e00200041006c006c0020005200690067006800740073002000520065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
