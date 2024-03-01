import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_0082Cb93593B658100Cdd7A00C874287F2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		author = "ditekSHen"
		id = "3e618656-6c9d-5172-bad4-f507cec1dc0c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L1374-L1385"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "df8eb4feef3992bae7097a05860f57a1408fc79d92741e3ea2f202d072d9f47e"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "d168d7cf7add6001df83af1fc603a459e11395a9077579abcdfd708ad7b7271f"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Sportsonline24 B.V." and pe.signatures[i].serial=="00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2")
}
