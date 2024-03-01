import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3769815A97A8Fb411E005282B37878E3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "da41e9a7-1660-5157-9148-f2f774df647a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5669-L5680"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "ccd548ebe2be2c7b44e6c39df50ffea4703d0b1decd78cc6fb4b3bbf9d85be0b"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c80fd3259af331743e35a2197f5f57061654860c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Yandex" and pe.signatures[i].serial=="37:69:81:5a:97:a8:fb:41:1e:00:52:82:b3:78:78:e3")
}
