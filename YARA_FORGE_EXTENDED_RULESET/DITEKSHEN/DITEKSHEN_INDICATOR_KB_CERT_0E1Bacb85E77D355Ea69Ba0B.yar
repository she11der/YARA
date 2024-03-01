import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0E1Bacb85E77D355Ea69Ba0B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "18e2dce1-c6aa-55d8-907a-75097feb7acf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L863-L874"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "f0753c83001e2b9d235afe51ce5d245e085551584ee052a35aaadd95c6c5eeb7"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6750c9224540d7606d3c82c7641f49147c1b3fd0"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BULDOK LIMITED" and pe.signatures[i].serial=="0e:1b:ac:b8:5e:77:d3:55:ea:69:ba:0b")
}
