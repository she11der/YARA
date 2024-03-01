import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0084888D5A12228E8950683Ecdab62Fe7A : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5036d604-55df-565a-b6db-c788da007ea8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4309-L4320"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4deda791923cdacccf57d54651ca44bd8c04d053a11ccf5700354f9f37be17de"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "390b23ed9750745e8441e35366b294a2a5c66fcd"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ub30 Limited" and pe.signatures[i].serial=="00:84:88:8d:5a:12:22:8e:89:50:68:3e:cd:ab:62:fe:7a")
}
