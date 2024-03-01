private rule SIGNATURE_BASE_Hatman_Dividers_PRIVATE : hatman
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "Florian Roth"
		id = "1612a184-e06c-5c1b-987d-04e330e17ed0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_hatman.yar#L38-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "92ec47ea81b78ec9b05f5c17164daaef7112c8590b4443f70cf3bf2efd108e1f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$div1 = { 9a 78 56 00 }
		$div2 = { 34 12 00 00 }

	condition:
		$div1 and $div2
}
