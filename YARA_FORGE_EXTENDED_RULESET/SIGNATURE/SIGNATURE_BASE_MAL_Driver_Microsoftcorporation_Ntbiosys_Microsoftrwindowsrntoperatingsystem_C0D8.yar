rule SIGNATURE_BASE_MAL_Driver_Microsoftcorporation_Ntbiosys_Microsoftrwindowsrntoperatingsystem_C0D8
{
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - ntbios_2.sys"
		author = "Florian Roth"
		id = "f16b4b22-985a-5d39-ae51-709aa9a69d8d"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/yara-rules_mal_drivers.yar#L83-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "c0d88db11d0f529754d290ed5f4c34b4dba8c4f2e5c4148866daabeab0d25f9c"
		hash = "96bf3ee7c6673b69c6aa173bb44e21fa636b1c2c73f4356a7599c121284a51cc"
		logic_hash = "74ad0b57644d82a77bc902786250156f5e3700671bdf9765055b5908dc345a67"
		score = 70
		quality = 85
		tags = ""

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]006e007400620069006f00730020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d006900630072006f0073006f0066007400200043006f00720070006f0072006100740069006f006e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0035002c00200030002c00200032002c00200031 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0035002c00200030002c00200032002c00200031 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006e007400620069006f002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0020004d006900630072006f0073006f00660074002800520029002000570069006e0064006f0077007300200028005200290020004e00540020004f007000650072006100740069006e0067002000530079007300740065006d }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006e007400620069006f0073002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]7248674362406709002000280043002900200032003000300033 }

	condition:
		all of them
}
