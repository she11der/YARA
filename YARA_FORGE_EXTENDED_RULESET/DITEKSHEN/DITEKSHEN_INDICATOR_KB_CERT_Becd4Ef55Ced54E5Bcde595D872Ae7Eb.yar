import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Becd4Ef55Ced54E5Bcde595D872Ae7Eb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "85835042-a4ab-5cb2-963d-4ef776b740d1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2965-L2976"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b573853cfb28bdbda37c929834faa15475707684edfe99f14174599faf7b4fb6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "72ae9b9a32b4c16b5a94e2b4587bc51a91b27052"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dedbfdefcac" and pe.signatures[i].serial=="be:cd:4e:f5:5c:ed:54:e5:bc:de:59:5d:87:2a:e7:eb")
}
