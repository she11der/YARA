import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_9F2492304Fc9C93844Dea7E5D6F0Ec77 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "73acca59-8362-5d34-b28a-71d141d3013a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3163-L3174"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9c76d5756cc79e96d194addc0e2c2c11fa4341ffa9df8f171f35df76cb9c56c0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "33015f23712f36e3ec310cfd1b16649abb645a98"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bbddebeea" and pe.signatures[i].serial=="9f:24:92:30:4f:c9:c9:38:44:de:a7:e5:d6:f0:ec:77")
}
