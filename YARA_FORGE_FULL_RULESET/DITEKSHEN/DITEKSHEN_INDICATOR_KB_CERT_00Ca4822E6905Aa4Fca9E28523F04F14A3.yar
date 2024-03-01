import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ca4822E6905Aa4Fca9E28523F04F14A3 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "713f84b3-b09a-5fcf-85ed-899be9f14b84"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5656-L5667"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "6e0d7abd82805019c6b1c9df2479489bbd3fe7a4a1703971c02324072692b1e5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "35ced9662401f10fa92282e062a8b5588e0c674d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ELISTREID, OOO" and pe.signatures[i].serial=="00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3")
}
