import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Fc7065Abf8303Fb472B8Af85918F5C24 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d8c25f8a-e129-5cd4-9e60-d2e7ebbb1ea6"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L120-L131"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8ce0d25ef802948f754f155010f42d76256895ebd6ffdce8d97063dada58e668"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b61a6607154d27d64de35e7529cb853dcb47f51f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and pe.signatures[i].serial=="00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24")
}
