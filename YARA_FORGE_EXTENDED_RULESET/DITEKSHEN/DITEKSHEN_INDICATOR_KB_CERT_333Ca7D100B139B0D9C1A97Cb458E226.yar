import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_333Ca7D100B139B0D9C1A97Cb458E226 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "dd5b3eb8-81c0-570d-9ec8-6a55eb7864f9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3880-L3891"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4519127b975d93297cca9b465ad88b3d38ad0fce0de182246dca3f000e2438be"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d618cf7ef3a674ff1ea50800b4d965de0ff463cb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FSE, d.o.o." and pe.signatures[i].serial=="33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26")
}
