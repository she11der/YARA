rule SIGNATURE_BASE_Apt_Nix_Elf_Derusbi_Linux_Sharedmemcreation_1 : FILE
{
	meta:
		description = "Detects Derusbi Backdoor ELF Shared Memory Creation"
		author = "Fidelis Cybersecurity"
		id = "068b7bea-853d-57e8-a9fe-8b451dbc7582"
		date = "2016-02-29"
		modified = "2023-12-05"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_turbo_campaign.yar#L85-L96"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "adbdccea9ea7aefcca18d659c027a49e7e2e053873b77ddaf369203b3e301033"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

	condition:
		uint32(0)==0x464C457F and any of them
}
