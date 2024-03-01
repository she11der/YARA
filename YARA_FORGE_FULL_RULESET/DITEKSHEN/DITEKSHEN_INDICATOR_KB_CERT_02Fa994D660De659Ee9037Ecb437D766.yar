import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_02Fa994D660De659Ee9037Ecb437D766 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "cb2aa5d6-913e-5d74-a903-1cb88fb63b1c"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6044-L6056"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		hash = "0868a2a7b5e276d3a4a40cdef994de934d33d62a689d7207a31fd57d012ef948"
		logic_hash = "04244701311fcdc77b1e3a8f20621e474ed607be3d109c629280d528e2f24e1f"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "0cb6bde041b58dbd4ec64bd5a3be38c50f17bb3d"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Piriform Software Ltd" and pe.signatures[i].serial=="02:fa:99:4d:66:0d:e6:59:ee:90:37:ec:b4:37:d7:66")
}
