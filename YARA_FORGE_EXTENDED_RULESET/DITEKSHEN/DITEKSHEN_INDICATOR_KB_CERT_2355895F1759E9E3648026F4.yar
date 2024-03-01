import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2355895F1759E9E3648026F4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d716ed7f-8886-587d-a868-805da13bb925"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4348-L4360"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "429375af70872755ab2d517b125042795c9a20238405a4af5b0caecc46a3f563"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f46d457898d436769f0c70127044e2019583ee16"
		hash1 = "f4f4a5953d0c87db611fa05bb51672591295049978a0e9e14eca8224254ecd7a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Avira Operations GmbH & Co. KG" and pe.signatures[i].serial=="23:55:89:5f:17:59:e9:e3:64:80:26:f4")
}
