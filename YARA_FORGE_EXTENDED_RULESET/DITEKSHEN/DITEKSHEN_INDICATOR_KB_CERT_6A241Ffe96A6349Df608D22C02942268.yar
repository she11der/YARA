import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_6A241Ffe96A6349Df608D22C02942268 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "571f5f11-576a-511b-975d-0643ae834502"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1491-L1502"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "41db1a9b11e2d5b8de5ba81496d0e76ea5eddacc01c77bc28c7e05496842df04"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f97f4b9953124091a5053712b2c22b845b587cb2655156dcafed202fa7ceeeb1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HELP, d.o.o." and pe.signatures[i].serial=="6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68")
}
