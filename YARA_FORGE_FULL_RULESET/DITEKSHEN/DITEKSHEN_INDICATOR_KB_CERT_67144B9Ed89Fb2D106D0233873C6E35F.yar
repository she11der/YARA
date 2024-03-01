import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_67144B9Ed89Fb2D106D0233873C6E35F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "f9806e55-9efa-504a-b27c-d3418fc5cd38"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5643-L5654"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9d3c39c590a75b3ea1d1f699bea279c0c68498e51e2ab7f4ad3e3f8857d6d668"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "5971faead4c86bf72e6ab36efc0376d4abfffeda"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Infosignal LLC" and pe.signatures[i].serial=="67:14:4b:9e:d8:9f:b2:d1:06:d0:23:38:73:c6:e3:5f")
}
