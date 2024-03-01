rule SIGNATURE_BASE_PUA_VULN_Driver_Avgtechnologiesczsro_Aswarpotsys_Avginternetsecuritysystem_9A54 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - aswArPot.sys, avgArPot.sys"
		author = "Florian Roth"
		id = "17496639-ec11-519b-8143-2d43568e09cd"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3548-L3568"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9a54ef5cfbe6db599322967ee2c84db7daabcb468be10a3ccfcaa0f64d9173c7"
		logic_hash = "a520f2236b800f2dd2b8ac9963b8e9ba3ce782cca2c1b2835540899da65168b5"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00410056004700200061006e0074006900200072006f006f0074006b00690074 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00410056004700200054006500630068006e006f006c006f006700690065007300200043005a002c00200073002e0072002e006f002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00310039002e0031002e0034003100330032002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00310039002e0031002e0034003100330032002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006100730077004100720050006f0074002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00410056004700200049006e007400650072006e00650074002000530065006300750072006900740079002000530079007300740065006d0020 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006100730077004100720050006f0074002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000310038002000410056004700200054006500630068006e006f006c006f006700690065007300200043005a002c00200073002e0072002e006f002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
