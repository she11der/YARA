import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_F6Ad45188E5566Aa317Be23B4B8B2C2F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d4afb6ed-1cfd-5c49-8959-0cf136d0e9f0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8821-L8834"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7afafea141727e2ed4c1975a18aa77b282c7d9ece5729dbd96cbb49cc2b393f1"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ae7db8b64e8abd9d36876f049b9770d90c0868d7fe1a2d37cf327df69fa2dbfe"
		reason = "Numando"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gary Kramlich" and pe.signatures[i].serial=="f6:ad:45:18:8e:55:66:aa:31:7b:e2:3b:4b:8b:2c:2f")
}
