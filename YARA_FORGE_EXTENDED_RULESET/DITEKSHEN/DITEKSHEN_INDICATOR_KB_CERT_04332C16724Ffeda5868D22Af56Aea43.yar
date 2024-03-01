import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_04332C16724Ffeda5868D22Af56Aea43 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "7e6be2f5-2f34-5337-8beb-4ccc6c50ad2d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L211-L222"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "338e7d9374de04d00162c9caf86d922f4d659b024ae7908f0e02ca4709a14a1d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "cba350fe1847a206580657758ad6813a9977c40e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and pe.signatures[i].serial=="04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43")
}
