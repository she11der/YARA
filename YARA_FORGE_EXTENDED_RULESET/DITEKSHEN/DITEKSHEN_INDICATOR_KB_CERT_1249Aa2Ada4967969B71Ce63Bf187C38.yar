import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1249Aa2Ada4967969B71Ce63Bf187C38 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3af35255-7583-5463-b130-ebc8abd4803b"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2482-L2493"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9f8ff46a3b0f5179c2c3b89e82188183fa399c67c3f0ebc28218cf3cb4ce5c70"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c139076033e8391c85ba05508c4017736a8a7d9c1350e6b5996dd94b374f403c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Umbrella LLC" and pe.signatures[i].serial=="12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38")
}
