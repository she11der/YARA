import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_B548765Eebe9468348Af40B9891C1E63 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "0ee1a31b-6324-5dbd-bd0d-765bc4891415"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6759-L6771"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "db8136f63657130bb3fe2527bb597e70bc3d46395aa3137810f4ee4b4de6c6ec"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5987703bc4a3c739f92af8fed1747394880e1a39"
		hash1 = "501dee454ba470aa09ceceb4c93ab7e9e913729e47fcc184a2e2d675f8234a58"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OSIRIS Corporation" and pe.signatures[i].serial=="b5:48:76:5e:eb:e9:46:83:48:af:40:b9:89:1c:1e:63")
}
