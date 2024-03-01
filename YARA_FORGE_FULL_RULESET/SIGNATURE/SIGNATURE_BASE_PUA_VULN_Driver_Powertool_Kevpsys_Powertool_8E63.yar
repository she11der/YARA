rule SIGNATURE_BASE_PUA_VULN_Driver_Powertool_Kevpsys_Powertool_8E63 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - kEvP64.sys"
		author = "Florian Roth"
		id = "0010c121-11bb-5068-a06d-aa136e5af0ad"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L3090-L3112"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "8e6363a6393eb4234667c6f614b2072e33512866b3204f8395bbe01530d63f2f"
		hash = "09b0e07af8b17db1d896b78da4dd3f55db76738ee1f4ced083a97d737334a184"
		hash = "1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c"
		logic_hash = "eb30a51b174462ff2b1b3d62b62fc572445293dfdc0f70f64c73c9b15cbf6c0b"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0050006f0077006500720054006f006f006c }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0050006f0077006500720054006f006f006c }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0031002e00300020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0031002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006b00450076005000360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0050006f0077006500720054006f006f006c }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006b00450076005000360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0050006f0077006500720054006f006f006c }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}