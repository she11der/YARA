import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_Ceb6B2Eec12934A64F75A4592159F084 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "a37bf0a2-3205-515c-9957-374108e199e9"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L5366-L5377"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "3e4aa8d970ead42bf1abb36a922ef31ac1b1aa308944cf099d6bbfb50e07c588"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "ccd30b68e37fc177b754250767a16062a711310a"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WMade by H5et.com" and pe.signatures[i].serial=="ce:b6:b2:ee:c1:29:34:a6:4f:75:a4:59:21:59:f0:84")
}
