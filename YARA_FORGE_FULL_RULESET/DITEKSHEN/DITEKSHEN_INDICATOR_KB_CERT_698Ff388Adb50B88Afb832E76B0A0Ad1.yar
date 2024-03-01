import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_698Ff388Adb50B88Afb832E76B0A0Ad1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8118e0ee-6214-54f3-b025-234f9e685832"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7981-L7994"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7734256201739dece5ae039d45ed79c74be6228f7da51fc82c0cfd2d4aacfd4b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "479e01dde7e7529ed4ad111a2d7b3b16fdc6fbe2ed0d6ff015c1c823ca0939db"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BELLAP LIMITED" and pe.signatures[i].serial=="69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1")
}
