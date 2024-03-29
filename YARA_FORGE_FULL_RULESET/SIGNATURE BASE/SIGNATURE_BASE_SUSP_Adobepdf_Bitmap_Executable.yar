import "pe"

rule SIGNATURE_BASE_SUSP_Adobepdf_Bitmap_Executable : FILE
{
	meta:
		description = "Detects a suspicious executable that contains a Adobe PDF icon and no shows no sign of actual Adobe software"
		author = "Florian Roth (Nextron Systems)"
		id = "86ebadd4-64a8-5290-b45e-ac125a10ea66"
		date = "2020-11-02"
		modified = "2023-12-05"
		reference = "https://mp.weixin.qq.com/s/3Pa3hiuZyQBspDzH0kGSHw"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_icon_anomalies.yar#L39-L68"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "a8ef5ce2e876565c7d6367ce555d00bd3535699f1907f867811f2f6749672c67"
		score = 60
		quality = 85
		tags = "FILE"
		hash1 = "13655f536fac31e6c2eaa9e6e113ada2a0b5e2b50a93b6bbfc0aaadd670cde9b"

	strings:
		$sc1 = { FF 00 CC FF FF 00 99 FF FF 00 66 FF FF 00 33 FF
               FF 80 00 FF FF 80 FF CC FF 80 CC CC FF C0 99 CC
               FF 80 66 CC FF 00 33 CC FF 00 00 CC FF 00 FF 99
               FF FF CC 99 FF FF 99 99 FF FF 66 99 FF FF 33 99
               FF 08 00 99 FF 88 FF 66 FF 88 CC 66 FF 88 99 66
               FF 88 66 66 FF 88 33 66 FF 05 00 66 FF 55 FF 33
               FF 55 CC 33 FF 55 99 33 FF 55 66 33 FF 58 33 33
               FF 01 00 33 FF 99 FF 00 FF 99 CC 00 FF 99 99 00
               FF 99 66 00 FF 58 33 00 FF 01 00 00 FF 99 FF FF
               CC 99 CC FF CC 99 99 FF CC 99 66 FF CC 58 33 FF
               CC 01 00 FF CC FF FF CC CC FF CC CC CC FF 99 CC
               CC FF 66 CC CC 58 33 CC CC 01 00 CC CC FF FF 99 }
		$fp1 = "Adobe" ascii wide fullword

	condition:
		uint16(0)==0x5a4d and $sc1 and not 1 of ($fp*) and pe.number_of_signatures<1
}
