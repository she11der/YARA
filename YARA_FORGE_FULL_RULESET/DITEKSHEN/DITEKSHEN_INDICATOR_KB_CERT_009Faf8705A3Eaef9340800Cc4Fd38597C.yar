import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_009Faf8705A3Eaef9340800Cc4Fd38597C : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "5b85e806-6b13-5356-a225-23399b947114"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3802-L3813"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "41c6561ef50950c7a5b4107b788e0469f77b9905b777edb24501649e4c313bd6"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "40c572cc19e7ca4c2fb89c96357eff4c7489958e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Tekhnokod LLC" and pe.signatures[i].serial=="00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c")
}
