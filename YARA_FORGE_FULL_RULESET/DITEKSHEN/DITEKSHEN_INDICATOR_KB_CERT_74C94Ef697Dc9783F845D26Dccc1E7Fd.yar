import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_74C94Ef697Dc9783F845D26Dccc1E7Fd : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "3cd08af1-8999-59a8-a679-a39871ecf68e"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6787-L6799"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "226dfe366c31e9cb38910df7d6cb2037c545745594fd133d7b7359175f153a90"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "6daa64d7af228de45ded86ad4d1aeaa360295f56"
		hash1 = "45e35c9b095871fbc9b85afff4e79dd36b7812b96a302e1ccc65ce7668667fe6"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CIBIKART d.o.o." and pe.signatures[i].serial=="74:c9:4e:f6:97:dc:97:83:f8:45:d2:6d:cc:c1:e7:fd")
}
