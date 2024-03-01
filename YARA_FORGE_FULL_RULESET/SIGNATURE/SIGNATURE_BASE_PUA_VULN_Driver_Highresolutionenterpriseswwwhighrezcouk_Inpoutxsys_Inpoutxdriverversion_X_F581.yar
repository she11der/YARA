rule SIGNATURE_BASE_PUA_VULN_Driver_Highresolutionenterpriseswwwhighrezcouk_Inpoutxsys_Inpoutxdriverversion_X_F581 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - inpoutx64.sys"
		author = "Florian Roth"
		id = "2103d553-3e8a-5f81-b54e-c125aa7746ca"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L5093-L5115"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "f581decc2888ef27ee1ea85ea23bbb5fb2fe6a554266ff5a1476acd1d29d53af"
		hash = "f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b"
		hash = "2d83ccb1ad9839c9f5b3f10b1f856177df1594c66cbbc7661677d4b462ebf44d"
		logic_hash = "ae7082fe90cf522f7bcbb615b751961972331147af1a56af961d35bf70e87f90"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004b00650072006e0065006c0020006c006500760065006c00200070006f0072007400200061006300630065007300730020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0048006900670068007200650073006f006c007500740069006f006e00200045006e0074006500720070007200690073006500730020005b007700770077002e006800690067006800720065007a002e0063006f002e0075006b005d }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e003200200078003600340020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e00320020007800360034 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0069006e0070006f00750074007800360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0069006e0070006f007500740078003600340020004400720069007600650072002000560065007200730069006f006e00200031002e0032 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0069006e0070006f00750074007800360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007000790072006900670068007400200028006300290020003200300030003800200048006900670068007200650073006f006c007500740069006f006e00200045006e007400650072007000720069007300650073002e00200050006f007200740069006f006e007300200043006f007000790072006900670068007400200028006300290020004c006f00670069007800340075 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}