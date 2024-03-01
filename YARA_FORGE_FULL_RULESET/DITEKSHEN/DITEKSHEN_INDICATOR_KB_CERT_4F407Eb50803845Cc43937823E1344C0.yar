import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4F407Eb50803845Cc43937823E1344C0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d5a6df76-bbbc-5025-b0c4-49e0034c03f3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L759-L770"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "bb01e912cf40155b0b00e1901bbb3235048ee033d0ddea7a809f0ce8e871e1ce"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0c1ffe7df27537a3dccbde6f7a49e38c4971e852"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and pe.signatures[i].serial=="4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0")
}
