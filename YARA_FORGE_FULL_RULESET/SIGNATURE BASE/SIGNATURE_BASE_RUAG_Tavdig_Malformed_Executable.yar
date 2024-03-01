rule SIGNATURE_BASE_RUAG_Tavdig_Malformed_Executable : FILE
{
	meta:
		description = "Detects an embedded executable with a malformed header - known from Tavdig malware"
		author = "Florian Roth (Nextron Systems)"
		id = "da6357d4-0cdb-5f30-9919-59858963cc41"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://goo.gl/N5MEj0"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_ruag.yar#L9-L19"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2a6eb90cc77f4556da0b5b0211bf0c4759dae0d78e9c6b765eff0e9a34f52e0f"
		score = 60
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x5a4d and uint32( uint32(0x3C))==0x0000AD0B
}
