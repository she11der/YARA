rule SIGNATURE_BASE_PUA_VULN_Driver_Zemanaltd_Zam_45F4 : FILE
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - zam64.sys"
		author = "Florian Roth"
		id = "56dc2fa5-c19c-5a77-9590-e7a957ccb27f"
		date = "2023-06-14"
		modified = "2023-12-05"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/yara-rules_vuln_drivers_strict.yar#L2669-L2686"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "45f42c5d874369d6be270ea27a5511efcca512aeac7977f83a51b7c4dee6b5ef"
		logic_hash = "539d1795ae819c2705e77cb41ec4248c7239ffa8cd805addbb9e5da5e98a83e2"
		score = 40
		quality = 85
		tags = "FILE"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005a0041004d }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005a0065006d0061006e00610020004c00740064002e }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0032002e00320030002e003800360035 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005a0041004d }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]005a0065006d0061006e00610020004c00740064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
