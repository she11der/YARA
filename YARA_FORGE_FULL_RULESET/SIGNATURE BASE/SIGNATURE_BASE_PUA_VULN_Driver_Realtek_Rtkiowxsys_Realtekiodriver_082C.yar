rule SIGNATURE_BASE_PUA_VULN_Driver_Realtek_Rtkiowxsys_Realtekiodriver_082C : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - rtkiow8x64.sys"
		author = "Florian Roth"
		id = "48446c71-f353-5f4f-a158-20bc7dec694f"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2132-L2152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "082c39fe2e3217004206535e271ebd45c11eb072efde4cc9885b25ba5c39f91d"
		logic_hash = "805a4da51dd1a85c46b830b747ed15f5cfb7539b42fd598987d3cd879d93cc97"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005200650061006c00740065006b00200049004f0020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005200650061006c00740065006b00200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020002000200020 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e003000300038002e0030003800320033002e0032003000310037 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e003000300038002e0030003800320033002e0032003000310037 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00720074006b0069006f00770038007800360034002e0073007900730020 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005200650061006c00740065006b00200049004f00200044007200690076006500720020002000200020002000200020002000200020002000200020002000200020002000200020002000200020 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00720074006b0069006f00770038007800360034002e0073007900730020 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003100370020005200650061006c00740065006b002000530065006d00690063006f006e0064007500630074006f007200200043006f00720070006f0072006100740069006f006e002e00200041006c006c002000520069006700680074002000520065007300650072007600650064002e002000200020002000200020002000200020002000200020 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}