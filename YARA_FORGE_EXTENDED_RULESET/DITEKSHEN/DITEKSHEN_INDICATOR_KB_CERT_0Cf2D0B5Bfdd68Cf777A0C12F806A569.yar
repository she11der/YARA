import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Cf2D0B5Bfdd68Cf777A0C12F806A569 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "610f4147-9b32-5d96-bf27-10a8e0c3c347"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L4817-L4828"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "d3e625c05e974650bb9750f6dadbbba5825a34ea10902c807b9da457902d2b59"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0c212cdf3d9a46621c19af5c494ff6bad25d3190"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROTIP d.o.o." and pe.signatures[i].serial=="0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69")
}
