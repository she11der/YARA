rule SIGNATURE_BASE_PUA_VULN_Driver_Avgtechnologiesczsro_Aswarpot_Avginternetsecuritysystem_0B54 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - aswArPot.sys, avgArPot.sys"
		author = "Florian Roth"
		id = "87caf882-a59a-55ca-89ce-a2c2115a1e50"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1051-L1071"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "0b542e47248611a1895018ec4f4033ea53464f259c74eb014d018b19ad818917"
		logic_hash = "264c22a6b54b47962561ea3d8400aab606dd2d28f5d288ba4777ff2ca290c38e"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00410056004700200041006e0074006900200052006f006f0074006b00690074 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00410056004700200054006500630068006e006f006c006f006700690065007300200043005a002c00200073002e0072002e006f002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]00320030002e0038002e003100330030002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]00320030002e0038002e003100330030002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006100730077004100720050006f0074 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00410056004700200049006e007400650072006e00650074002000530065006300750072006900740079002000530079007300740065006d0020 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006100730077004100720050006f0074002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000320030002000410056004700200054006500630068006e006f006c006f006700690065007300200043005a002c00200073002e0072002e006f002e }

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
