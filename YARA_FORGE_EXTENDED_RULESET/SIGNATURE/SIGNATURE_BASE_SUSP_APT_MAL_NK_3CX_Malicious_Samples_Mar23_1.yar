import "pe"

rule SIGNATURE_BASE_SUSP_APT_MAL_NK_3CX_Malicious_Samples_Mar23_1
{
	meta:
		description = "Detects marker found in malicious DLLs related to 3CX compromise"
		author = "X__Junior, Florian Roth (Nextron Systems)"
		id = "9fc6eb94-d02f-5bcd-9f55-b6c6a8301b4f"
		date = "2023-03-29"
		modified = "2023-04-20"
		reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_mal_3cx_compromise_mar23.yar#L81-L98"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "dcce1f5e769a2821d746a960cd333f8042fb71c8469aa41c29bbbd0dce79369c"
		score = 75
		quality = 85
		tags = ""
		hash1 = "7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896"
		hash2 = "c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02"
		hash3 = "cc4eedb7b1f77f02b962f4b05278fa7f8082708b5a12cacf928118520762b5e2"

	strings:
		$opx1 = { 41 80 7C 00 FD FE 75 ?? 41 80 7C 00 FE ED 75 ?? 41 80 7C 00 FF FA 75 ?? 41 80 3C 00 CE }
		$opx2 = { 80 78 ?? FE 75 ?? 80 78 ?? ED 75 ?? 80 38 FA 75 ?? 80 78 ?? CE }

	condition:
		1 of them
}
