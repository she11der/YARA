rule SIGNATURE_BASE_PUA_VULN_Driver_Sunmicrosystemsinc_Vboxdrvsys_Sunvirtualbox_R_7539 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - VBoxDrv.sys"
		author = "Florian Roth"
		id = "5ccaf486-04c4-5066-b307-e76b6e484d01"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L4304-L4324"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7539157df91923d4575f7f57c8eb8b0fd87f064c919c1db85e73eebb2910b60c"
		logic_hash = "dd40b144e403136b4359106d2efeb24335b83ffc13a62fdce7c9bd602dc45506"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005600690072007400750061006c0042006f007800200053007500700070006f007200740020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00530075006e0020004d006900630072006f00730079007300740065006d0073002c00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0033002e0030002e0030002e007200340039003300310035 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0033002e0030002e0030002e007200340039003300310035 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00560042006f0078004400720076002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]00530075006e0020005600690072007400750061006c0042006f0078 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00560042006f0078004400720076002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300039002000530075006e0020004d006900630072006f00730079007300740065006d0073002c00200049006e0063002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}