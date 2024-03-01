import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Ab1D5E43E4Dde77221381E21A764C082 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "55135b31-93d7-512f-8506-51e49bc3dc92"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3646-L3657"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3746c3494dca7fd2e0c7ab6641fe9ebbb8519df755022a3bde99c192158e4299"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b84a817517ed50dbae5439be54248d30bd7a3290"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Dadddbffbfcbdaaeeccecbbffac" and pe.signatures[i].serial=="00:ab:1d:5e:43:e4:dd:e7:72:21:38:1e:21:a7:64:c0:82")
}
