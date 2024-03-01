import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_7Ddd3796A427B42F2E52D7C7Af0Ca54F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2619669f-cceb-5177-9738-d28236e1344e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5139-L5150"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "15df43212a842936e2ea0d834797f11fe80af3d376a19aa9a806aa6ed793e679"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b5cd5a485dee4a82f34c98b3f108579e8501fdea"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Fobos" and pe.signatures[i].serial=="7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f")
}
