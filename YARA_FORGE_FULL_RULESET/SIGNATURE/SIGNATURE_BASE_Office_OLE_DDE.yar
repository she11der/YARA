rule SIGNATURE_BASE_Office_OLE_DDE : FILE
{
	meta:
		description = "Detects DDE in MS Office documents"
		author = "NVISO Labs"
		id = "2ead3cc9-f517-5916-93c9-1393362aa45d"
		date = "2017-10-12"
		modified = "2023-12-05"
		reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_dde_in_office_docs.yar#L48-L63"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2d2f7dce166dc8ef8aba7e8eaafaf4d1bb34cdc1ce97d34125a65147cf5e08ac"
		score = 50
		quality = 60
		tags = "FILE"

	strings:
		$a = /\x13\s*DDE\b[^\x14]+/ nocase
		$r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
		$r2 = "Adobe ARM Installer"

	condition:
		uint32be(0)==0xD0CF11E0 and $a and not 1 of ($r*)
}
