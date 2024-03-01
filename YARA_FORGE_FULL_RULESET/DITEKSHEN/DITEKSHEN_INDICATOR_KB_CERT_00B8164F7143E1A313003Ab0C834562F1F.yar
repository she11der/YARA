import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00B8164F7143E1A313003Ab0C834562F1F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "d6ebdfb9-55db-58e2-89a8-d47d747e3432"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1465-L1476"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "77f8f125740de97e6fdd98103eefa2a431df0cbe2e7de44f7e863e22ebcfea4c"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "263c636c5de68f0cd2adf31b7aebc18a5e00fc47a5e2124e2a5613b9a0247c1e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ekitai Data Inc." and pe.signatures[i].serial=="00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f")
}
