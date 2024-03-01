import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_A32B8B4F1Be43C23Eb2848Ab4Ef06Bb2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f0baf7ea-7022-5834-a46c-b67bfbe706d0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8026-L8039"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "438667b55f23b689627fc1e5bce0e53b960ef51d1a7d3203e398c59bd94ffe93"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f7a578c93fd98ade3d259ac47f152d8c9115bc5df7e2f57d107a66db3f833f0f"
		reason = "NetSupport RAT"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pak El AB" and pe.signatures[i].serial=="a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2")
}
