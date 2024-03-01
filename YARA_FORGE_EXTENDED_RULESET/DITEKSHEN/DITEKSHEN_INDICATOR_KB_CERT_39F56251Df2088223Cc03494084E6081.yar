import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_39F56251Df2088223Cc03494084E6081 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "4b5c27e0-0b3e-52e6-a867-1c2adadf3af3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L1663-L1674"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "dc757f831b2537f12151f4f9e886ccf83bacfbcaea3ce12b2199f13ae00b199e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "66f32cf78b8f685a2c6f5bf361c9b0f9a9678de11a8e7931e2205d0ef65af05c"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Inter Med Pty. Ltd." and pe.signatures[i].serial=="39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81")
}
