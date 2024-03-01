rule SIGNATURE_BASE_MAL_Driver_Legalcorp_Pciexpressvideocapture_FD22
{
	meta:
		description = "Detects malicious driver mentioned in LOLDrivers project using VersionInfo values from the PE header - PcieCubed.sys"
		author = "Florian Roth"
		id = "c9b28922-d4c7-5c09-9df8-b7b8d8ffc2e8"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/yara-rules_mal_drivers.yar#L61-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "fd223833abffa9cd6cc1848d77599673643585925a7ee51259d67c44d361cce8"
		logic_hash = "4c47a159595f420c520e6924238bd260f49ccf163208713c72c62638b13756d9"
		score = 70
		quality = 85
		tags = ""

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005000430049006500200056006900640065006f00200043006100700074007500720065 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004c006500670061006c00200043006f00720070002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0030002e00310035 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0030002e00310035 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0050004300490020004500780070007200650073007300200056006900640065006f00200043006100700074007500720065 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]005000630069006500430075006200650064002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00320030003100360020004c006500670061006c }

	condition:
		all of them
}
