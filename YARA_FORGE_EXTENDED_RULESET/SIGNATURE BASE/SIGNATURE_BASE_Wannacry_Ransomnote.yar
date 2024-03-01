rule SIGNATURE_BASE_Wannacry_Ransomnote : FILE
{
	meta:
		description = "Detects WannaCry Ransomware Note"
		author = "Florian Roth (Nextron Systems)"
		id = "65ce8faf-0981-5382-bc15-f094ccaa9f54"
		date = "2017-05-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/HG2j5T"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_wannacry.yar#L103-L117"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "da814848f4616166bd7b92fa1d55a54b565fa8e6036cb895e5795448e989a99d"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"

	strings:
		$s1 = "A:  Don't worry about decryption." fullword ascii
		$s2 = "Q:  What's wrong with my files?" fullword ascii

	condition:
		( uint16(0)==0x3a51 and filesize <2KB and all of them )
}
