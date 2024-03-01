import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_025020668F51235E9Ecfff8Cf00Da63E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5b9af281-09b0-5df5-af3b-4868a7243636"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7085-L7096"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c99caf6ada228fe1229ea8e8ca0b160468f044a9a1e13ed9a83c12afeae337a1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "59f82837fa672a81841d8fa4d3ba290395c10200"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Knassar DK ApS" and pe.signatures[i].serial=="02:50:20:66:8f:51:23:5e:9e:cf:ff:8c:f0:0d:a6:3e")
}
