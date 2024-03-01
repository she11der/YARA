import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_24E4A2B3Db6Be1007B9Ddc91995Bc0C8 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "47ca5986-3de8-56f2-a15d-ef588d8a9e03"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8341-L8354"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "71d1f8e9113170f410007b31c0d7316c537001b2a761f1e35d6bd2aa0b39f2d9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "005af6c8e9f06a2258c2df70785a5622c8d10d982fdc7f4dbe2f53af6e860359"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLY BETTER s.r.o." and pe.signatures[i].serial=="24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8")
}
