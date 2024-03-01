import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Bce1D49Ff444D032Ba3Dda6394A311E9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ee980353-b7c3-5738-84ae-e51c021e6597"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1949-L1960"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "eeb1556808e790eea964658a8499ec2d9cc5638bf696fbbade2bc08a29fb3e65"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e9a9ef5dfca4d2e720e86443c6d491175f0e329ab109141e6e2ee4f0e33f2e38"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DECIPHER MEDIA LLC" and pe.signatures[i].serial=="bc:e1:d4:9f:f4:44:d0:32:ba:3d:da:63:94:a3:11:e9")
}
