import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_4C450Eccd61D334E0Afb2B2D9Bb1D812 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "116c86c1-facf-5b69-94f1-3f0f81c38a7d"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L850-L861"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "70851d76af4a4dfe8f1ca4de9925f030d9b937050876828775b78eddd123e3cd"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4c450eccd61d334e0afb2b2d9bb1d812"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ANJELA KEY LIMITED" and pe.signatures[i].serial=="4c:45:0e:cc:d6:1d:33:4e:0a:fb:2b:2d:9b:b1:d8:12")
}
