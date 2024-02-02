rule ESET_Apt_Windows_TA410_X4_Hash_Fct___FILE
{
	meta:
		description = "Matches X4 hash function found in TA410 X4"
		author = "ESET Research"
		id = "5ca435a4-7c6e-594d-8c4d-d577735884e6"
		date = "2020-10-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L151-L187"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "3b2d44cb7685a99e9aeb08f886f6876d43ee99d1e52e40705c3fa97ce3bfa9a0"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            0F B6 01
            84 C0
            74 ??
            48 69 D2 83 00 00 00
            48 0F BE C0
            48 03 D0
            48 FF C1
            E9 ?? ?? ?? ??
}