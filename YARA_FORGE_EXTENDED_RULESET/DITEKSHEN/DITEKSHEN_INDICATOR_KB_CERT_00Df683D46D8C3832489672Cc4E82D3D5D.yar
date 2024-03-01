import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Df683D46D8C3832489672Cc4E82D3D5D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "532ee72a-00f6-513e-b4f9-0827f77d643e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1387-L1398"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "153fdb25769d912732a1fb4ecc757fc8c7e4766cd6588ea16d9cf642b4be8bf6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8b63c5ea8d9e4797d77574f35d1c2fdff650511264b12ce2818c46b19929095b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Osatokio Oy" and pe.signatures[i].serial=="00:df:68:3d:46:d8:c3:83:24:89:67:2c:c4:e8:2d:3d:5d")
}
