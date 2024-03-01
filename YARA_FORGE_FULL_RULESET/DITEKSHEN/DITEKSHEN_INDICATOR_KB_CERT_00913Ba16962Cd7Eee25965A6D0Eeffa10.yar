import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00913Ba16962Cd7Eee25965A6D0Eeffa10 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7a053089-44c8-5f30-8eee-dcd4ba24efe8"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4927-L4938"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a2e729c053d1a9d5895dc2247ea0804525f8f1744875d5c2f96b4255ad325dc5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "079aeb295c8e27ac8d9be79c8b0aaf66a0ef15de"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JMT TRADING GROUP INC" and pe.signatures[i].serial=="00:91:3b:a1:69:62:cd:7e:ee:25:96:5a:6d:0e:ef:fa:10")
}
