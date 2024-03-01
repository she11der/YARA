import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7D36Cbb64Bc9Add17Ba71737D3Ecceca : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "23786dd4-2ad2-5d86-a0d2-46bc5f1825eb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5763-L5774"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "070600994d7e137a769432e7c5995dac90f01cbce2c50de4c5baecea5d556baf"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a7287460dcf02e38484937b121ce8548191d4e64"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LTD SERVICES LIMITED" and pe.signatures[i].serial=="7d:36:cb:b6:4b:c9:ad:d1:7b:a7:17:37:d3:ec:ce:ca")
}
