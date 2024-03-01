import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0537F25A88E24Cafdd7919Fa301E8146 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b0dd33b4-2040-5021-bebc-5ca26d75f14c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L6215-L6227"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		hash = "72ac61e6311f2a6430d005052dbc0cc58587e7b75722b5e34a71081370f4ddd5"
		logic_hash = "8cd68612354a756c4a52d6baea9ef6ed74c94f5fcf25baa2f72c1131e0828f84"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "922211f5ab4521941d26915aeb82ee728f931082"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Avira Operations GmbH & Co. KG" and pe.signatures[i].serial=="05:37:f2:5a:88:e2:4c:af:dd:79:19:fa:30:1e:81:46")
}
