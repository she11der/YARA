import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_08653Ef2Ed9E6Ebb56Ffa7E93F963235 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "8883185a-8239-5648-bebc-3a4c3578a7d6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L2625-L2636"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "b0e35f2dbd27de0dc9ea6ee7958c477e6a154bc4c8bb5484ba85ed5732502645"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "1567d022b47704a1fd7ab71ff60a121d0c1df33a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Haw Farm LIMITED" and pe.signatures[i].serial=="08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35")
}
