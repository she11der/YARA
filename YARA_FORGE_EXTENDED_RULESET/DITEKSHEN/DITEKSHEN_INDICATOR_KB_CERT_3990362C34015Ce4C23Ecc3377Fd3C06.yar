import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_3990362C34015Ce4C23Ecc3377Fd3C06 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e76824c2-6ee7-5117-a83f-0b8e4f2d3b61"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3490-L3501"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "5e91a10f5027cae35524bef326edf7d5bf3df5bbc37c111b01e33f7667b03ce3"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "48444dec9d6839734d8383b110faabe05e697d45"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RZOH ApS" and pe.signatures[i].serial=="39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06")
}
