import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1F23F001458716D435Cca1A55D660Ec5 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "16a904e4-bf1a-5530-9269-d92c0f1bb4d3"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L2339-L2350"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3e91429f7b25ad54103ee230a36d4b51060adb458b533b9cbd00178a02676629"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "934d9357b6fb96f7fb8c461dd86824b3eed5f44a65c10383fe0be742c8c9b60e"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Ringen" and pe.signatures[i].serial=="1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5")
}
