import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_234Bf4Ef892Df307373638014B35Ab37 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "af403af3-2c10-5742-80f2-c507695106a2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4049-L4060"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d01dbb798b309927e666e5e68c56c6eeabad7ccbc427d62f0507597c6e9e7aa7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "348f7e395c77e29c1e17ef9d9bd24481657c7ae7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].serial=="23:4b:f4:ef:89:2d:f3:07:37:36:38:01:4b:35:ab:37")
}
