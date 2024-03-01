import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_70E1Ebd170Db8102D8C28E58392E5632 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "f5ccfbdd-d72d-5060-84e6-0ab8477f73fe"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1439-L1450"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b639424c97fb1da440c458cf5cb8f04562292284db7b576c0676a632704f597b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "90d67006be03f2254e1da76d4ea7dc24372c4f30b652857890f9d9a391e9279c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Equal Cash Technologies Limited" and pe.signatures[i].serial=="70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32")
}
