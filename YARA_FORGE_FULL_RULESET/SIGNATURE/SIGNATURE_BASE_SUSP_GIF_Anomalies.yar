import "pe"

rule SIGNATURE_BASE_SUSP_GIF_Anomalies : FILE
{
	meta:
		description = "Detects files with GIF headers and format anomalies - which means that this image could be an obfuscated file of a different type"
		author = "Florian Roth (Nextron Systems)"
		id = "2e77c2ff-a8f6-5444-a93d-843312640a28"
		date = "2020-07-02"
		modified = "2023-12-05"
		reference = "https://en.wikipedia.org/wiki/GIF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_file_anomalies.yar#L17-L30"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "64d17c8de72600cd889a802fd002faaaf9a3a17f7fa157ae5b2b620b28e6c439"
		score = 60
		quality = 85
		tags = "FILE"

	condition:
		uint16(0)==0x4947 and uint8(2)==0x46 and uint8(11)!=0x00 and uint8(12)!=0x00 and uint8( filesize -1)!=0x3b
}
