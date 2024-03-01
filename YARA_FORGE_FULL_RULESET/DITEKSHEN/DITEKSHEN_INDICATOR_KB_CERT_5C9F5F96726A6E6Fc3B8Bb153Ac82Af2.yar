import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5C9F5F96726A6E6Fc3B8Bb153Ac82Af2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f79e1a89-c7b4-5390-b20b-3f563f409cfe"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7816-L7829"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "da76d86509aee2f9cac992e6b081dce5e68c747ad34abd2daeb32e6e390b880b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "285925b7c7c692f8d71d980dcf2ddb4c208a0f7b826ead34db402755d1a0f6de"
		reason = "IcedID"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "1105 SOFTWARE LLC" and pe.signatures[i].serial=="5c:9f:5f:96:72:6a:6e:6f:c3:b8:bb:15:3a:c8:2a:f2")
}
