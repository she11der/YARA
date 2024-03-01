import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_1B1E87E90519D7273C0033Bf489B798F : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "b154ae08-108c-5980-a611-5e086877af2a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5471-L5483"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		hash = "84cef0aed269e6213bfa213d95a3db625bcdde130f33bf4227436985e4473252"
		logic_hash = "b47f80ecc895e73d69c60a5e88d6a6c95fcb9bddb30f14a1421b68aabc2290c9"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ef09824554f85603c9ffb1cecbfe06ae489a9583"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IBIS, OOO" and pe.signatures[i].serial=="1b:1e:87:e9:05:19:d7:27:3c:00:33:bf:48:9b:79:8f")
}
