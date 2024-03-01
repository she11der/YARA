import "pe"

rule DITEKSHEN_INDICATOR_KB_CERT_54Cc50D147Fa549E3F721C754E4E3A91 : FILE
{
	meta:
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		author = "ditekSHen"
		id = "2007dabd-74c0-5cc7-986c-21fb1df9136a"
		date = "2023-12-08"
		modified = "2023-12-08"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_certs.yar#L6714-L6726"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "367237a9370542a4506fb13683f0a91e4bf5eb871e4b9f62b4cae8316bdf2d9a"
		score = 75
		quality = 75
		tags = "FILE"
		thumbprint = "e3143f0df21fced02fe5525b297ed4cd389c66e3"
		hash1 = "85adf569d259dc53c5099fea6e90ff3a614a406b4308ebdf9f40e8bed151f526"
		importance = 20

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Ralink Technology Corporation" and pe.signatures[i].serial=="54:cc:50:d1:47:fa:54:9e:3f:72:1c:75:4e:4e:3a:91")
}
