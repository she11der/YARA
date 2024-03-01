rule SIGNATURE_BASE_PUA_VULN_Driver_Advancedmicrodevices_Amdryzenmasterdriversys_Amdryzenmasterservicedriver_9B1A : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - AMDRyzenMasterDriver.sys"
		author = "Florian Roth"
		id = "9dd62c3a-8f3c-5df0-a6a2-fcaa72c4ed16"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L1834-L1854"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "9b1ac756e35f795dd91adbc841e78db23cb7165280f8d4a01df663128b66d194"
		logic_hash = "fcef672d2e2c24f4b1323554ca206f3bd67657af96ad774056e5fd0181cc7ac7"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0041004d0044002000520079007a0065006e0020004d00610073007400650072002000530065007200760069006300650020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0041006400760061006e0063006500640020004d006900630072006f00200044006500760069006300650073 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0031002e0030002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0031002e0030002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0041004d004400520079007a0065006e004d00610073007400650072004400720069007600650072002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0041004d0044002000520079007a0065006e0020004d00610073007400650072002000530065007200760069006300650020004400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0041004d004400520079007a0065006e004d00610073007400650072004400720069007600650072002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000a90020003200300031003700200041004d0044002c00200049006e0063002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
