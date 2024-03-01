import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5Fb6Bae8834Edd8D3D58818Edc86D7D7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "65f5e05c-f5cd-53ba-b4ec-7f412aa63796"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2456-L2467"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9cec6eae024d738c68d670fb61f7667bdc156245da83e5d0ae0f2012baa5bc0a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "026868bbc22c6a37094851e0c6f372da90a8776b01f024badb03033706828088"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tramplink LLC" and pe.signatures[i].serial=="5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7")
}
