import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_09C89De6F64A7Fdf657E69353C5Fdd44 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "613c4253-8a53-5faa-8376-10c9a35805cf"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L276-L287"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7fcb517a4160226cf89c13b5b27310d1e8a02d3f164a338a8d2901ef604f1d8a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "7ad763dfdaabc1c5a8d1be582ec17d4cdcbd1aeb"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and pe.signatures[i].serial=="09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44")
}
