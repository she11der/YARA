import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Fd8C468Cc1B45C9Cfb41Cbd8C835Cc9E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "836af706-3a82-5aaf-9a96-244eef5820b2"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L55-L66"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "495ec6dbfdec3f608e387280e2d34093bb4965f5ada7c101e3119ae970eaf80d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "08fc56a14dcdc9e67b9a890b65064b8279176057"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and pe.signatures[i].serial=="fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e")
}
