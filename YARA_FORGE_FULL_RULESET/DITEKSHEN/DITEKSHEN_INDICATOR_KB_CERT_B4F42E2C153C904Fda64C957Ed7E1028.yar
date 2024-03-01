import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_B4F42E2C153C904Fda64C957Ed7E1028 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d284b7f0-9728-5755-87d5-f8251903e778"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2796-L2807"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "d47f85602234eae7629b778b09ed5c3656c6afa8b6a7ba42cc46f451202a16c0"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ed4c50ab4f173cf46386a73226fa4dac9cadc1c4"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NONO spol. s r.o." and pe.signatures[i].serial=="b4:f4:2e:2c:15:3c:90:4f:da:64:c9:57:ed:7e:10:28")
}
