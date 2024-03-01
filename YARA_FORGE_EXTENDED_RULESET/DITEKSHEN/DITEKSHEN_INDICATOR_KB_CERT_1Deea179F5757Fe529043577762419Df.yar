import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1Deea179F5757Fe529043577762419Df : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a6b9b9e4-0998-5f67-8c12-7628ba3a5a56"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8371-L8384"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b521363d1d38a4ed1b2b4126aec85ed6bffc23dc4e30f6f6c942e1fa96b0dd8d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "9c4e87ccd6004a70115f8e654b8cc1a80d488876ff2e4e7db598303fa41b3fef"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPIRIT CONSULTING s. r. o." and pe.signatures[i].serial=="1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df")
}
