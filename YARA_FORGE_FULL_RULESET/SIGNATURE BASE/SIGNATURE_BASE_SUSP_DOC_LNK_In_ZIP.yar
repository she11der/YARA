rule SIGNATURE_BASE_SUSP_DOC_LNK_In_ZIP : FILE
{
	meta:
		description = "Detects suspicious .doc.lnk file in ZIP archive"
		author = "Florian Roth (Nextron Systems)"
		id = "9c140d02-3b18-5faf-bb1d-2eb5c07a23dc"
		date = "2019-07-02"
		modified = "2023-12-05"
		reference = "https://twitter.com/RedDrip7/status/1145877272945025029"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_lnk_files.yar#L53-L66"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ef4cdaad05af12f210aa6324a1e34a42843f814c59fb0085ac18370917ad4866"
		score = 50
		quality = 85
		tags = "FILE"
		hash1 = "7ea4f77cac557044e72a8e280372a2abe072f2ad98b5a4fbed4e2229e780173a"

	strings:
		$s1 = ".doc.lnk" fullword ascii

	condition:
		uint16(0)==0x4b50 and 1 of them
}
