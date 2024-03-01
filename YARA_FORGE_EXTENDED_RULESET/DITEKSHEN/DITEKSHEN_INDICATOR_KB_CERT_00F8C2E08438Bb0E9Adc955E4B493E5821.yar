import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F8C2E08438Bb0E9Adc955E4B493E5821 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "75f505d0-c79a-5eab-a61f-29ec238ac045"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1975-L1986"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "2258ea96b56acb3025b5b2f39c07d482c375e75323d6f8e8ded91b8dab00656e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "459ef82eb5756e85922a4687d66bd6a0195834f955ede35ae6c3039d97b00b5f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and pe.signatures[i].serial=="00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21")
}
