rule SIGNATURE_BASE_SUSP_ELF_SPARC_Hunting_SBZ_Modulestruct : FILE
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth for FP reduction reasons"
		id = "909746f1-44f5-597b-bdb2-2a1396d4b8c7"
		date = "2023-04-02"
		modified = "2023-05-08"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_sparc_sbz_apr23.yar#L49-L65"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dc9608c769dcb14ba01559bfe2e8ed03eebf5695b867b53742f26e3fcce389ca"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$be = { 02 02 00 00 01 C1 00 07 }
		$le = { 02 02 00 00 07 00 C1 01 }

	condition:
		uint32be(0)==0x7f454c46 and ($be or $le)
}
