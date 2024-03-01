rule SIGNATURE_BASE_Templatr : FILE
{
	meta:
		description = "Chinese Hacktool Set - file templatr.php"
		author = "Florian Roth (Nextron Systems)"
		id = "b361a49d-1e05-5597-bf8b-735e04397ffa"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_webshells.yar#L361-L374"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "759df470103d36a12c7d8cf4883b0c58fe98156b"
		logic_hash = "80d207ee47c0c602ddd281e0e187b83cdb4f1385f4b46ad2a4f5630b8f9e96a1"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "eval(gzinflate(base64_decode('" ascii

	condition:
		filesize <70KB and all of them
}
