rule ESET_Apt_Windows_TA410_Tendyron_Downloader
{
	meta:
		description = "TA410 Tendyron Downloader"
		author = "ESET Research"
		id = "afd8a2a7-8d58-5a96-b9e0-6f8b859e83c5"
		date = "2020-12-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L75-L107"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "16030a78ae9af8783f5913644294ceff861c8264ead8ca99435032be6d7949ef"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            8A 10
            80 F2 5C
            80 C2 5C
            88 10
            40
            83 E9 01
            75 ??
}