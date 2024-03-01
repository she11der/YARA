import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00E5Ad42C509A7C24605530D35832C091E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "44615e9d-6677-5642-b56d-82c0577f758c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1897-L1908"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "8d76474257ee9a24d4785ddd119e586712a157ff7b420a7db2b8efe06c43f76c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "17b1f6ffc569acd2cf803c4ac24a7f9828d8d14f6b057e65efdb5c93cc729351"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "VESNA, OOO" and pe.signatures[i].serial=="00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e")
}
