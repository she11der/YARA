import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_66390Fc17786D4A342F0Ee89996D6522 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "202e4270-9b49-5516-8188-a64bd528a9c4"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6987-L6998"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a38d09beee8ddaa6e8273e04fe3c5cc9ff9a4e55344e2b9191bb3e5928e9e79b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "80e8620ff16598cc1e157a2b7df17d528b03b6e5"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Logitech Z-" and pe.signatures[i].serial=="66:39:0f:c1:77:86:d4:a3:42:f0:ee:89:99:6d:65:22")
}
