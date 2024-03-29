import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Dbc03Ca7E6Ae6Db6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "801bc9fc-0bd6-5c46-8c45-8cb06cfc4309"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8416-L8429"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "7d188663b00870e98984b4be4c72b0fd183b5fb8dd61512c1d65d386f1ebad0a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e059776cb5e640569a06c2548e87af5bd655f5d4815b8f6e9482835455930987"
		reason = "CobaltStrike"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SPIDER DEVELOPMENTS PTY LTD" and pe.signatures[i].serial=="db:c0:3c:a7:e6:ae:6d:b6")
}
