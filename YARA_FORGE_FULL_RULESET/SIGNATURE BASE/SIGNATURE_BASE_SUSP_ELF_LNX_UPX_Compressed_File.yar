rule SIGNATURE_BASE_SUSP_ELF_LNX_UPX_Compressed_File : FILE
{
	meta:
		description = "Detects a suspicious ELF binary with UPX compression"
		author = "Florian Roth (Nextron Systems)"
		id = "078937de-59b3-538e-a5c3-57f4e6050212"
		date = "2018-12-12"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_elf_file_anomalies.yar#L2-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0d310de1ab68bd6da9ae057c7edea0d6b24d408f85ec40c2306f1ac8a2bc2f55"
		score = 40
		quality = 85
		tags = "FILE"
		hash1 = "038ff8b2fef16f8ee9d70e6c219c5f380afe1a21761791e8cbda21fa4d09fdb4"

	strings:
		$s1 = "PROT_EXEC|PROT_WRITE failed." fullword ascii
		$s2 = "$Id: UPX" fullword ascii
		$s3 = "$Info: This file is packed with the UPX executable packer" ascii
		$fp1 = "check your UCL installation !"

	condition:
		uint16(0)==0x457f and filesize <2000KB and filesize >30KB and 2 of ($s*) and not 1 of ($fp*)
}
