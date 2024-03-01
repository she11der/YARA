import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_072472F2386F4608A0790Da2Be8A48F7 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "79f1e6da-003a-5291-a60c-7693ca2efbeb"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L7140-L7151"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "32b61f42ee9f3109c747e8a159376d03349d8a5061be0c31504e929cb3c3042e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e2a79e70b7a16a6fc2af7fbdc3d2cbfd3ef66978"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FOXIT SOFTWARE INC." and pe.signatures[i].serial=="07:24:72:f2:38:6f:46:08:a0:79:0d:a2:be:8a:48:f7")
}
