rule SIGNATURE_BASE_SUSP_ELF_SPARC_Hunting_SBZ_Obfuscation : FILE
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth to avoid elf module import"
		id = "15ee9a66-d823-508c-a14c-2c6ff45f47e5"
		date = "2023-04-02"
		modified = "2023-05-08"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_sparc_sbz_apr23.yar#L2-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "3d45dc8d8dbc62cee6b7ec4aa842eaa88bd23aea17e995eef4850fd91e7069a3"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$xor_block = { 9A 18 E0 47 9A 1B 40 01 9A 18 80 0D }
		$a1 = "SUNW_"

	condition:
		uint32be(0)==0x7f454c46 and $a1 and $xor_block
}
