import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5F11C47D3F8C468E5D38279De98078Ce : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d7ec5ceb-df6d-518c-977d-84ab2a40f6ed"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7056-L7067"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "82db6d0b96303be79aa9a0980a4ce491a1216adbba65443e8e59c5cf69a4a1e4"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "29bbee51837dbc00c8e949ff2c0226d4bbb3722c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Atera Networks LTD." and pe.signatures[i].serial=="5f:11:c4:7d:3f:8c:46:8e:5d:38:27:9d:e9:80:78:ce")
}
