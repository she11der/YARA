import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0Ddeb53F957337Fbeaf98C4A615B149D : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "13347f66-c726-59be-9d0e-871512335bbd"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2703-L2714"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "4932dcea41879fd29250456cfef7a32a1303f599adbd4b61d91cb2e7e22cf5a2"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "91cabea509662626e34326687348caf2dd3b4bba"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Mozilla Corporation" and pe.signatures[i].serial=="0d:de:b5:3f:95:73:37:fb:ea:f9:8c:4a:61:5b:14:9d")
}
