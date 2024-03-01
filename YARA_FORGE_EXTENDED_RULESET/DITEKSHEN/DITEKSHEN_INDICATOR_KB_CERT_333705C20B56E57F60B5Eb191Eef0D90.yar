import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_333705C20B56E57F60B5Eb191Eef0D90 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e868c3ff-a701-59bd-9cd6-bf49305fe28a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7198-L7209"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f5ca35381842a0ea7c319d8388753347a72fc6df746064e520794aeb4b6724d0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "44f0f77d8b649579fa6f88ae9fa4b4206b90b120"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TASK Holding ApS" and pe.signatures[i].serial=="33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90")
}
