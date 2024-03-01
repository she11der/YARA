rule SIGNATURE_BASE_SUSP_ELF_SPARC_Hunting_SBZ_Uniquestrings
{
	meta:
		description = "This rule is UNTESTED against a large dataset and is for hunting purposes only."
		author = "netadr, modified by Florian Roth for performance reasons"
		id = "d2f70d10-412e-5e83-ba4f-eac251012dc1"
		date = "2023-04-02"
		modified = "2023-05-08"
		reference = "https://netadr.github.io/blog/a-quick-glimpse-sbz/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_sparc_sbz_apr23.yar#L26-L47"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bb95fc6bda0a0ed8ffc6db9734c725c487b0e70909d60119bf58d60987daaaeb"
		score = 60
		quality = 85
		tags = ""

	strings:
		$s1 = "<%u>[%s] Event #%u: "
		$s2 = "lprc:%08X" ascii fullword
		$s3 = "diuXxobB"
		$s4 = "CHM_FW"

	condition:
		2 of ($*)
}
