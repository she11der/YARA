import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_2Ba40F65086686Dd4Ab7171E : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "13909741-cba3-5143-86eb-bcc227cfaa9c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5630-L5641"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "8ed65c0b5d231be9dbbe34da493087d1bf83cf21c401435fed7e2851acdb6f60"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "842f81869c2f4f2ba2a7e6513501166e2679108a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RITEIL SISTEMS LLC" and pe.signatures[i].serial=="2b:a4:0f:65:08:66:86:dd:4a:b7:17:1e")
}
