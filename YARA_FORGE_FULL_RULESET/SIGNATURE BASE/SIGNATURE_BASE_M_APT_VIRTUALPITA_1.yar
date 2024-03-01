rule SIGNATURE_BASE_M_APT_VIRTUALPITA_1 : FILE
{
	meta:
		description = "Finds opcodes to set a port to bind on 2233, encompassing the setsockopt(), htons(), and bind() from 40973d to 409791 in fe34b7c071d96dac498b72a4a07cb246 (may produce some FPs - comment by Florian Roth)"
		author = "Mandiant"
		id = "bdfbe29a-f7db-50d9-a909-d4ca96cc0731"
		date = "2023-11-25"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_unc3886_virtualpita.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fe34b7c071d96dac498b72a4a07cb246"
		logic_hash = "7641f964cc4a7671a9a3438aad1c653ef3fda3887313846cbe838b275a098190"
		score = 60
		quality = 45
		tags = "FILE"

	strings:
		$x = {8b ?? ?? 4? b8 04 00 00 00 [0 - 4] ba 02 00 00 00 be 01 00 00 00 [0 - 2] e8 ?? ?? ?? ?? 89 4? ?? 83 7? ?? 00 79 [0 - 50] ba 10 00 00 00 [0 - 10] e8}

	condition:
		uint32(0)==0x464c457f and all of them
}
