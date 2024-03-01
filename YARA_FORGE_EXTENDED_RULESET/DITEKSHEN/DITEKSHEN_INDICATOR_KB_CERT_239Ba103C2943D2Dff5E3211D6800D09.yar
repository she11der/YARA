import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_239Ba103C2943D2Dff5E3211D6800D09 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1444a44e-2f45-547f-a5fc-0941edd506bc"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3295-L3306"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b155ba969334945013af40fbf43b8318a221f6212c4a29e0ee98bc02bb9acafb"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d8ea0533af5c180ce1f4d6bc377b736208b3efbb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bcafaecbecacbca" and pe.signatures[i].serial=="23:9b:a1:03:c2:94:3d:2d:ff:5e:32:11:d6:80:0d:09")
}
