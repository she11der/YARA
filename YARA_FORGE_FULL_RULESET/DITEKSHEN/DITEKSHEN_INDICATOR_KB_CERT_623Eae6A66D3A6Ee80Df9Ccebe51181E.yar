import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_623Eae6A66D3A6Ee80Df9Ccebe51181E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7c3b85e4-8ce7-5c48-8f3b-e237a5cae9a0"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L8536-L8549"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "79fceab5a19025d25abb12a8e6f57f8a930d348d538d9c556b6d4fc461af66f2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "21c4e9af43068d041e6aec84341ae89cabb9917792c4bc372eced059555bb845"
		reason = "Quakbot"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "GAIN AI LTD" and pe.signatures[i].serial=="62:3e:ae:6a:66:d3:a6:ee:80:df:9c:ce:be:51:18:1e")
}
