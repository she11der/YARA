rule SIGNATURE_BASE_PUA_VULN_Driver_Phoenixtechnologies_Agentsys_Driveragent_4045 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - Agent64.sys"
		author = "Florian Roth"
		id = "41ccdc0b-ec41-51b3-9039-bf5206f9a79f"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1641-L1665"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4045ae77859b1dbf13972451972eaaf6f3c97bea423e9e78f1c2f14330cd47ca"
		hash = "8cb62c5d41148de416014f80bd1fd033fd4d2bd504cb05b90eeb6992a382d58f"
		hash = "6948480954137987a0be626c24cf594390960242cd75f094cd6aaa5c2e7a54fa"
		hash = "b1d96233235a62dbb21b8dbe2d1ae333199669f67664b107bff1ad49b41d9414"
		hash = "05f052c64d192cf69a462a5ec16dda0d43ca5d0245900c9fcb9201685a2e7748"
		logic_hash = "1902f186f263eaeaf3de6712a8fe2c01f2225f7ba051f4020de27832e197e256"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004400720069007600650072004100670065006e0074002000440069007200650063007400200049002f004f00200066006f0072002000360034002d006200690074002000570069006e0064006f00770073 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00500068006f0065006e0069007800200054006500630068006e006f006c006f0067006900650073 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004100670065006e007400360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004400720069007600650072004100670065006e0074 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004100670065006e007400360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0045006e0054006500630068002000540061006900770061006e002c00200031003900390037002d0032003000300039 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}