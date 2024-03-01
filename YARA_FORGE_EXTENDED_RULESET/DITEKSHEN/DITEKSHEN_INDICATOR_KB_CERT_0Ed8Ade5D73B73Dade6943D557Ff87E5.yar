import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ed8Ade5D73B73Dade6943D557Ff87E5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "ebdab290-d388-528e-b392-0ae87941b69d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L484-L495"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "e2e269a83a86567bf359996945cddc597406033aa7c5a7acf30b58d30816b28f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9bbd8476bf8b62be738437af628d525895a2c9c9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rumikon LLC" and pe.signatures[i].serial=="0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5")
}
