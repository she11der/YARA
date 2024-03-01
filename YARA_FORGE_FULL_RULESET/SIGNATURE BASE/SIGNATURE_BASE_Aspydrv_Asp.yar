rule SIGNATURE_BASE_Aspydrv_Asp
{
	meta:
		description = "Semi-Auto-generated  - file aspydrv.asp.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "4420d13e-7015-5083-ba08-b41bf28b00c2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4861-L4874"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "1c01f8a88baee39aa1cebec644bbcb99"
		logic_hash = "64912d7521d4bff33b5f3a78525bf4ed94246f5933753bed7ca02bedffc85f0f"
		score = 60
		quality = 85
		tags = ""

	strings:
		$s0 = "If mcolFormElem.Exists(LCase(sIndex)) Then Form = mcolFormElem.Item(LCase(sIndex))"
		$s1 = "password"
		$s2 = "session(\"shagman\")="

	condition:
		2 of them
}
