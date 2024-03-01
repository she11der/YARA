import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_19F613Cf951D49814250701037442Ee2 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "780c515e-811c-5f44-97a2-9ed93a7d9d89"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L7367-L7384"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1ea5f770ddbb7dba836049bec0c7b73cd5bc6a87514f8ea00288cb9d52d17651"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint1 = "6feab07fa782fc7fbddde8465815f4d04d79ad97"
		thumbprint2 = "41aaafa56a30badb291e96d31ed15a9343ba7ed3"
		hash1 = "9629cae6d009dadc60e49f5b4a492bd1169d93f17afa76bee27c37be5bca3015"
		hash2 = "3b3281feef6d8e0eda2ab7232bd93f7c747bee143c2dfce15d23a1869bf0eddf"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cooler Master" and (pe.signatures[i].serial=="19:f6:13:cf:95:1d:49:81:42:50:70:10:37:44:2e:e2" or pe.signatures[i].serial=="6b:e8:ee:f0:82:a4:f5:96:4c:75:0b:c0:07:24:f6:4a"))
}
