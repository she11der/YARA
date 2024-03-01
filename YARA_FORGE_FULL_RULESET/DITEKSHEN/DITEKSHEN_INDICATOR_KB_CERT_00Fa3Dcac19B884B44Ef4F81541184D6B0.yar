import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_00Fa3Dcac19B884B44Ef4F81541184D6B0 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "a188e033-4381-5ff0-8f54-f36571ae7097"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1426-L1437"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "7e9e2b22f6f2cfd5d7c962fb43c85d703d0a600f954f614073c708f4b881d90e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6557117e37296d7fdcac23f20b57e3d52cabdb8e5aa24d3b78536379d57845be"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unicom Ltd" and pe.signatures[i].serial=="00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0")
}
