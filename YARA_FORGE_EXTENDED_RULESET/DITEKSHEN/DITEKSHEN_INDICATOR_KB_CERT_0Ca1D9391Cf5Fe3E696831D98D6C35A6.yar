import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ca1D9391Cf5Fe3E696831D98D6C35A6 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e2f026d6-031d-5058-a7f1-fc492ea47908"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L3737-L3748"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "4c60dea4fe28c2799dc88712275e62a795c848120c4b463109942b8d9bc29a81"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0689776ca5ca0ca9641329dc29efdb61302d7378"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "www.norton.com" and pe.signatures[i].serial=="0c:a1:d9:39:1c:f5:fe:3e:69:68:31:d9:8d:6c:35:a6")
}
