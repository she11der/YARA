import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_008B7369B2F0C313634A1C1Dfc4A828A54 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e4da4da0-68f1-548b-b307-e11ad6def316"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5815-L5826"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "857eaa56ff5106e3808750b8833fd33a328b53a04f6fd2939aca30dbc6048329"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1cad5864bcc0f6aa20b99a081501a104b633dddd"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LFpKdFUgpGKj" and pe.signatures[i].serial=="00:8b:73:69:b2:f0:c3:13:63:4a:1c:1d:fc:4a:82:8a:54")
}
