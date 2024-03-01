import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4929Ab561C812Af93Ddb9758B545F546 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e57e442a-6fe3-5d09-bbc4-d290a7a80090"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1598-L1609"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "a03f37840b24456a4a2ef8e7c456dc99396886682156e4e95f7547bf38d8dc4d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0946bf998f8a463a1c167637537f3eba35205b748efc444a2e7f935dc8dd6dc7"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Everything Wow s.r.o." and pe.signatures[i].serial=="49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46")
}
