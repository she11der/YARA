rule SIGNATURE_BASE_PUA_VULN_Driver_Msi_Ntiolibxsys_Ntiolib_09BE : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - NTIOLib.sys"
		author = "Florian Roth"
		id = "30b7487c-d5b7-52b1-a209-f6eb01f0f406"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L4235-L4255"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "09bedbf7a41e0f8dabe4f41d331db58373ce15b2e9204540873a1884f38bdde1"
		logic_hash = "23f5a77bae75d686a980e65dd6efe4ad216a60d75631fed169a83cc88d64675e"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004e00540049004f004c00690062 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d00530049 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0030002e0032 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0030002e0032 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004e00540049004f004c00690062005f005800360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004e00540049004f004c00690062 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004e00540049004f004c00690062005f005800360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003100360020004d006900630072006f002d005300740061007200200049004e00540027004c00200043004f002e002c0020004c00540044002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
