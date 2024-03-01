import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_5A9D897077A22Afe7Ad4C4A01Df6C418 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "e44fcc54-9d0c-5b9b-a34a-03f31ae5333d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2248-L2259"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "f82b59f5d1996ae37b0cb7f7a799e2fcc7d9da0ffddfe63cbbb84b6f0e7e7b23"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "50fa9d22557354a078767cb61f93de9abe491e3a8cb69c280796c7c20eabd5b9"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Klarens LLC" and pe.signatures[i].serial=="5a:9d:89:70:77:a2:2a:fe:7a:d4:c4:a0:1d:f6:c4:18")
}
