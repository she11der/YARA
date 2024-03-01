import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_38B0Eaa7C533051A456Fb96C4Ecf91C4 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "1133fb37-2616-5d95-83da-554d9a5a5373"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2560-L2571"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "3ea8eaf1fc17075a8c1f34f9b1d8a987071d58a4b68bed70db763402a9a6de97"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "8e2e69b1202210dc9d2155a0f974ab8c325d5297"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marianne Septier" and pe.signatures[i].serial=="38:b0:ea:a7:c5:33:05:1a:45:6f:b9:6c:4e:cf:91:c4")
}
