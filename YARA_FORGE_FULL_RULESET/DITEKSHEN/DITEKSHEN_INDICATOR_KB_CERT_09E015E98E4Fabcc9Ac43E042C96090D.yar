import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_09E015E98E4Fabcc9Ac43E042C96090D : FILE
{
	meta:
		description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
		author = "ditekSHen"
		id = "577cff87-b676-598b-acea-e7c01df0ef15"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://blog.macnica.net/blog/2020/11/dtrack.html"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2729-L2742"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "77f9f50c6dd862419edaa7c3fcee0ce3f607a5b7b939d7844969082ab9777bbf"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "04e407118516053ff248503b31d6eec6daf4a809"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jetico Inc. Oy" and pe.signatures[i].serial=="09:e0:15:e9:8e:4f:ab:cc:9a:c4:3e:04:2c:96:09:0d")
}
