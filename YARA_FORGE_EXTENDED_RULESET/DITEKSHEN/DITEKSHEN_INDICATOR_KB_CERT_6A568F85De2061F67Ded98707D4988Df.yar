import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6A568F85De2061F67Ded98707D4988Df : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "ed8748ce-cd90-527b-a58e-da9c7164ed18"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5112-L5123"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f1aea9f6237cfbda49fea6d38ece935f9d4cc5abc678590c63b9a339aa37e104"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ed7e16a65294086fbdeee09c562b0722fdb2db48"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Apladis" and pe.signatures[i].serial=="6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df")
}
