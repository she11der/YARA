import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Df45B36C9D0Bd248C3F9494E7Ca822 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "95100ec5-01bf-5a5a-a703-b10d320beed1"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6470-L6481"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "40f4ad4183ca0bc76295c535a9286994ef0e3f8ac932372328016d543bb58ab5"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "4b1efa2410d9aab12af6c0b624a3738dd06d3353"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MPO STORITVE d.o.o." and pe.signatures[i].serial=="df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22")
}
