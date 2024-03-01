rule SIGNATURE_BASE_PUA_VULN_Driver_Gigabytetechnologycoltd_Gdrvsys_Gigabytesoftwaredriver_8B92 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - gdrv.sys"
		author = "Florian Roth"
		id = "158dd78f-3665-59d6-8528-f4489791d55e"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3839-L3859"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8b92cdb91a2e2fab3881d54f5862e723826b759749f837a11c9e9d85d52095a2"
		logic_hash = "565bd93231c1cffbb52efc9fedae7c41593ba93a2540dadf199806793359f67d"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0047004900470041002d00420059005400450020004e006f006e0050006e00500020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0047004900470041002d004200590054004500200054004500430048004e004f004c004f0047005900200043004f002e002c0020004c00540044002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0030002e0031 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0030002e0031 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0067006400720076002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0047004900470041002d004200590054004500200053006f0066007400770061007200650020006400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0067006400720076002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000310037 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
