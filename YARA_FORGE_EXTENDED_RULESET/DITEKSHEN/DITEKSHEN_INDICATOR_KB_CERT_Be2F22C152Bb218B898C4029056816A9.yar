import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Be2F22C152Bb218B898C4029056816A9 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "50c0cee3-39d5-5c57-9515-11356f8cab93"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7712-L7726"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "9eba1585d92b184afb7b75b84e0010539ac42ca27e4d5d8bccee6b01e3471cca"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "85fe11e799609306516d82e026d4baef4c1e9ad3"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Marts GmbH" and (pe.signatures[i].serial=="be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9" or pe.signatures[i].serial=="00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9"))
}
