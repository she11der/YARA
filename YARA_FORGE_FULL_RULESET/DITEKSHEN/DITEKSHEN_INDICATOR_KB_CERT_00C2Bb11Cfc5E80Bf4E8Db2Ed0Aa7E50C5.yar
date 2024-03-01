import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00C2Bb11Cfc5E80Bf4E8Db2Ed0Aa7E50C5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "d22ee868-71a7-52f4-93f3-b04b105fd399"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2092-L2103"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "e54eeea70e85396b26fe188b848ef37c619aae5fc909c1a06ad0bc42fb9b0468"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "f1044e01ff30d14a3f6c89effae9dbcd2b43658a3f7885c109f6e22af1a8da4b"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rooth Media Enterprises Limited" and pe.signatures[i].serial=="00:c2:bb:11:cf:c5:e8:0b:f4:e8:db:2e:d0:aa:7e:50:c5")
}
