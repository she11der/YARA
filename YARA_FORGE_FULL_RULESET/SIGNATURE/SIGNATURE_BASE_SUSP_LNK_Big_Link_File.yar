rule SIGNATURE_BASE_SUSP_LNK_Big_Link_File : FILE
{
	meta:
		description = "Detects a suspiciously big LNK file - maybe with embedded content"
		author = "Florian Roth (Nextron Systems)"
		id = "e130f213-53fc-56d6-b1d5-0508a7e18e61"
		date = "2018-05-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_susp_lnk.yar#L2-L12"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6e44483583249939494e76f14b022e698ba59dfe8b58133a69135144ef60c743"
		score = 65
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x004c and uint32(4)==0x00021401 and filesize >200KB
}
