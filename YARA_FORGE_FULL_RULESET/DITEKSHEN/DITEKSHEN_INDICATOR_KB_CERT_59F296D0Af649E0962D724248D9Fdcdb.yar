import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_59F296D0Af649E0962D724248D9Fdcdb : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c9423cae-07a7-5ecb-966d-b1636563934a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7756-L7769"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0212033b2ea12f568a3c2e4d3768194c8035c6b6ebf054af90fe82ffcd7e6a5b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ce2aa31a714cc05f86d726a959f6655efc40777aa474fb6b9689154fdc918a44"
		reason = "DarkGate"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MK ZN s.r.o." and pe.signatures[i].serial=="59:f2:96:d0:af:64:9e:09:62:d7:24:24:8d:9f:dc:db")
}
