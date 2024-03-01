import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_08622B9Dd9D78E67678Ecc21E026522E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "922282e9-9f34-537b-9fd1-283ae44b9b54"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L4457-L4468"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7e572c4241d92ad34efd91c3f6338da4093c83d84a734766448ac7cb2a72bc0c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "a7d86073742ea55af134e07a00aefa355dc123be"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kayak Republic af 2015 APS" and pe.signatures[i].serial=="08:62:2b:9d:d9:d7:8e:67:67:8e:cc:21:e0:26:52:2e")
}
