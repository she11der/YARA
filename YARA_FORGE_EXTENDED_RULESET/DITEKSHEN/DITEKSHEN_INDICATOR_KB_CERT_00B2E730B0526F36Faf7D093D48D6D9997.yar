import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B2E730B0526F36Faf7D093D48D6D9997 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7c74d3aa-dc4f-51ed-9574-74e0539cd22b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1546-L1557"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "16c50b7a2b7b55662d5cdb2261a6b352657b2689a9328916fcf63ddfbef5d08f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "10dd41eb9225b615e6e4f1dce6690bd2c8d055f07d4238db902f3263e62a04a9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bamboo Connect s.r.o." and pe.signatures[i].serial=="00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97")
}
