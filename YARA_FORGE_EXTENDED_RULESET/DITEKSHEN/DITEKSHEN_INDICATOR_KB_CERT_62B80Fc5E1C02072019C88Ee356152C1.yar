import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_62B80Fc5E1C02072019C88Ee356152C1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "08db7669-c3d6-5f27-988e-96e9fc0a60f3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3555-L3566"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "c06e31f5a071ff7c87af216d22bffa2970372fa341ad2593ef0c3c6a71dac945"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0a83c0f116020fc1f43558a9a08b1f8bcbb809e0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Inversum" and pe.signatures[i].serial=="62:b8:0f:c5:e1:c0:20:72:01:9c:88:ee:35:61:52:c1")
}
