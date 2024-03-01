rule SIGNATURE_BASE_PUA_VULN_Driver_Avastsoftware_Aswarpot_Avastantivirus_36E3 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - aswArPot.sys, avgArPot.sys"
		author = "Florian Roth"
		id = "6ea52f09-df49-5bc4-a3bc-34a80e78b739"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L5000-L5020"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "36e3127f045ef1fa7426a3ff8c441092d3b66923d2b69826034e48306609e289"
		logic_hash = "c8c776a3ef3f452b261c7348f0634f9bac7e00f5028eeb56af41461d240a5216"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0041007600610073007400200041006e0074006900200052006f006f0074006b00690074 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0041005600410053005400200053006f006600740077006100720065 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00320030002e0033002e00360038002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00320030002e0033002e00360038002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006100730077004100720050006f0074 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0041007600610073007400200041006e00740069007600690072007500730020 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006100730077004100720050006f0074002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400200028006300290020003200300032003000200041005600410053005400200053006f006600740077006100720065 }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
