import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_047801D5B55C800B48411Fd8C320Ca5B : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "750b5b0d-7752-5407-a29e-3272b764a276"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5335-L5346"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "5e64b59f3d7f7554a482eaa32f5eac80f289bf57865a21381a3c1c78b1dabcab"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "00c49b8d6fd7d2aa26faad8e5a31f93a15d66d09"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "LICHFIELD STUDIO GLASS LIMITED" and pe.signatures[i].serial=="04:78:01:d5:b5:5c:80:0b:48:41:1f:d8:c3:20:ca:5b")
}
