import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_28F6Ca1F249Cfb6Bdb16Bc57Aaf0Bd79 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b0568efe-d0cc-528d-a9b4-fdb8106c3d0f"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3004-L3015"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c27ad7caa87b366593b82ff5e2b38bda5383e178e2cc01121aaaa5e90beaec86"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0811c227816282094d5212d3c9116593f70077ab"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cdcafaabbdcaaaeaaee" and pe.signatures[i].serial=="28:f6:ca:1f:24:9c:fb:6b:db:16:bc:57:aa:f0:bd:79")
}
