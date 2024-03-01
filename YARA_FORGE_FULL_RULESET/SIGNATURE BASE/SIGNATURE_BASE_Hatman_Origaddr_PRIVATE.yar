private rule SIGNATURE_BASE_Hatman_Origaddr_PRIVATE : hatman
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "5eb29f1f-f49f-54e9-8a9e-ba10fc9c826e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hatman.yar#L51-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e9f775326dc0496662fbec98438e0273c51a88a434542dfcabd6e8b11131ab3e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$oaddr_be = { 3c 60 00 03  60 63 96 f4  4e 80 00 20 }
		$oaddr_le = { 03 00 60 3c  f4 96 63 60  20 00 80 4e }

	condition:
		$oaddr_be or $oaddr_le
}
