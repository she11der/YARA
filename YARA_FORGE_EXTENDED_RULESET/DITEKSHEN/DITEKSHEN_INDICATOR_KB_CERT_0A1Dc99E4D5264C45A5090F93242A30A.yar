import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0A1Dc99E4D5264C45A5090F93242A30A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "8efea9da-a3ae-5af3-83b2-cac5baa4fa89"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L29-L40"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "cb230503e17e93f78b04723c32d7ce66bdf146846e0208d268eebc0e446a6917"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "17680b1ebaa74f94272957da11e914a3a545f16f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and pe.signatures[i].serial=="0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a")
}
