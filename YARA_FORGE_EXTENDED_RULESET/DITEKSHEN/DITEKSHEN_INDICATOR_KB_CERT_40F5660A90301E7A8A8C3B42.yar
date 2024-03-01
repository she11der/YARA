import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_40F5660A90301E7A8A8C3B42 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "c3c8fbdf-49ca-5898-b267-74256154973a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L8176-L8189"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ed584aa8ad833066ed9f7ddbf98dc75efe88e0b7e69f564a90eade63dc2aee2d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "2ac041e3c46c82fbcee34617ee31336e845e18efe6b9ae5c8811351db5b56da2"
		reason = "Cobalt Strike"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Booz Allen Hamilton Inc." and pe.signatures[i].serial=="40:f5:66:0a:90:30:1e:7a:8a:8c:3b:42")
}
