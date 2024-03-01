import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4B03Cabe6A0481F17A2Dbeb9Aefad425 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3995296a-58ce-5615-8524-525698af3537"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2378-L2389"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e3c0d68a65bc53b83a48310857605afda0004b4122201c18a66fea085a210924"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2e86cb95aa7e4c1f396e236b41bb184787274bb286909b60790b98f713b58777"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RASSVET, OOO" and pe.signatures[i].serial=="4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25")
}
