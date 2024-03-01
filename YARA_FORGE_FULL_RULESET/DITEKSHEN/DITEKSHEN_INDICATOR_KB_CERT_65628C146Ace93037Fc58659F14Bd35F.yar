import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_65628C146Ace93037Fc58659F14Bd35F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "9104836a-3385-5b78-9e1d-705b7ed4b721"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L3958-L3969"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "a6b4cc307d6e6f4d5d275ef0765a7082216b1d277c9b1328abe7cb2c2497e411"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "b59165451be46b8d72d09191d0961c755d0107c8"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ESET, spol. s r.o." and pe.signatures[i].serial=="65:62:8c:14:6a:ce:93:03:7f:c5:86:59:f1:4b:d3:5f")
}
