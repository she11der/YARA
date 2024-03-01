import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00F675139Ea68B897A865A98F8E4611F00 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "7035ed66-73f9-568e-9698-13d9bbede64e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3529-L3540"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "9893e21fd2d5a475c9defb484921de17f4afc00619be413b9d5d55095e7f596a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "06d46ee9037080c003983d76be3216b7cad528f8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BS TEHNIK d.o.o." and pe.signatures[i].serial=="00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00")
}
