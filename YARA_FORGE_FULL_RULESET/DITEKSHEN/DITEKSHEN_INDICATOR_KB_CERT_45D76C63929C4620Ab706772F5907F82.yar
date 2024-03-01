import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_45D76C63929C4620Ab706772F5907F82 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "6ade67b1-cff5-5e5d-917c-f31010e09b82"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L575-L586"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9854a8812f55f2ae7cddc714b780def3d0511b236685a17ffe202711237c4b7e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "67c4afae16e5e2f98fe26b4597365b3cfed68b58"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NEON CRAYON LIMITED" and pe.signatures[i].serial=="45:d7:6c:63:92:9c:46:20:ab:70:67:72:f5:90:7f:82")
}
