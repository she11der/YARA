import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_07Cef66A71C35Bc3Aed6D100C6493863 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e07b0a2c-64ff-5e12-9f19-00a67a13fb89"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4875-L4886"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "24b89e65bc9d60a60e57f749735214c462e56c3194906e4bca52d74463617be4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9f65b1f0bed6e58ecdcc30b81b08b350fcc966a1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fubon Technologies Ltd" and pe.signatures[i].serial=="07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63")
}
