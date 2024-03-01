import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00D3D74Ae548830D5B1Bca9856E16C564A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "692ef744-9609-5cb1-b425-3bacf012fcdb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4127-L4138"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c72f10af530a6af4526ad956ef6058d097417a8fe3b902e3c7cba27b04e0c2c1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "3f996b75900d566bc178f36b3f4968e2a08365e8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Insite Software Inc." and pe.signatures[i].serial=="00:d3:d7:4a:e5:48:83:0d:5b:1b:ca:98:56:e1:6c:56:4a")
}
