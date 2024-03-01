import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Aff762E907F0644E76Ed8A7485Fb12A1 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "92113fc4-ef5b-5e86-bc8e-baf342ddf276"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2040-L2051"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "0be4642f6aaf2183d593240efcc8c2046970d3806a67ff53ca4ce7ee85df90e5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7b0c55ae9f8f5d82edbc3741ea633ae272bbb2207da8e88694e06d966d86bc63"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Lets Start SP Z O O" and pe.signatures[i].serial=="00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1")
}
