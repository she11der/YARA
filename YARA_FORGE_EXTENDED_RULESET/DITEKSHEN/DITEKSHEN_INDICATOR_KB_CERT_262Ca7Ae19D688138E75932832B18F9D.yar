import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_262Ca7Ae19D688138E75932832B18F9D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "891717e4-502f-5820-903c-3d9f2751a9d3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_certs.yar#L5695-L5706"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "0e6e75206bea63856e4ab07ff9b1220448f3cad6d845ae09703b9e836015520d"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "c5d34eb26bbb3fcb274f9e9cb37f5ae6612747a1"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bisoyetutu Ltd Ltd" and pe.signatures[i].serial=="26:2c:a7:ae:19:d6:88:13:8e:75:93:28:32:b1:8f:9d")
}
