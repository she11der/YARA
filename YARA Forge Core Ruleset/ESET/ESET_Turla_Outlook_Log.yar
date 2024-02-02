rule ESET_Turla_Outlook_Log
{
	meta:
		description = "First bytes of the encrypted Turla Outlook logs"
		author = "ESET Research"
		id = "b0031c08-8418-5a02-8a2c-daa7236f46f0"
		date = "2018-08-22"
		modified = "2018-09-05"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/turla/turla-outlook.yar#L93-L107"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "e7dc00c33a643c0940aaea2096d099192b27df3c81c518f1dc2b3d45a0a74312"
		score = 75
		quality = 80
		tags = ""
		contact = "github@eset.com"
		license = "BSD 2-Clause"

	strings:
		$s1 = {01 87 C9 75 C8 69 98 AC E0 C9 7B [21] EB BB 60 BB 5A}

	condition:
		$s1 at 0
}