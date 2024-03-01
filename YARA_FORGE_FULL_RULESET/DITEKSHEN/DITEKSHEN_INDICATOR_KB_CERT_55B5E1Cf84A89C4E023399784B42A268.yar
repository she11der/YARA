import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_55B5E1Cf84A89C4E023399784B42A268 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "de2890d4-3758-5e90-a9af-dc519f0b9e4c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2978-L2989"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "37f08db5373cf46da7c0a4a03af21559fdcddb2481f935d5cece55a1fb4abc3c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "940345ed6266b67a768296ad49e51bbaa6ee8e97"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Fbbdefaccbbcdc" and pe.signatures[i].serial=="55:b5:e1:cf:84:a8:9c:4e:02:33:99:78:4b:42:a2:68")
}
