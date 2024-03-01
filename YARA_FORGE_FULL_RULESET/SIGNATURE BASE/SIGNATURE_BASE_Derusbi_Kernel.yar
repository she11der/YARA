rule SIGNATURE_BASE_Derusbi_Kernel : FILE
{
	meta:
		description = "Derusbi Driver version"
		author = "Airbus Defence and Space Cybersecurity CSIRT - Fabien Perigaud"
		id = "a60ab93a-e2be-53ee-a7da-56c763bc5533"
		date = "2015-12-09"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_derusbi.yar#L9-L22"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d5a0ce0b0116c3a84d52c22369dbf3cb9cf3ad8f8a05cea5565ba9bb99255fab"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$token1 = "$$$--Hello"
		$token2 = "Wrod--$$$"
		$class = ".?AVPCC_BASEMOD@@"

	condition:
		uint16(0)==0x5A4D and $token1 and $token2 and $class
}
