import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_E9268Ed63A7D7E9Dfd40A664Ddfbaf18 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "59e63c76-1051-5274-b886-fcd75c8b0b38"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8566-L8579"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "62b9ea3c5197635db2101972af951f4afbd9b311b3c8286525bbd5b5baa17c41"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0767b9ab857b8e24282b80a7368323689a842e6c8b5a00a4f965c03e375e8b0d"
		reason = "Hive"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Casta, s.r.o." and pe.signatures[i].serial=="e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18")
}
