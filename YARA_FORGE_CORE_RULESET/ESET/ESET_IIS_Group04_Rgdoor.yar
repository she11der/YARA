import "pe"

rule ESET_IIS_Group04_Rgdoor
{
	meta:
		description = "Detects Group 4 native IIS malware family (RGDoor)"
		author = "ESET Research"
		id = "64a0e664-a4d9-555b-a11b-5f7d9d0678b1"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/badiis/badiis.yar#L178-L199"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "be615dc0cc8bf0fd52cc5a88a3759c1cb1cd18703de74d16f5cce3eabccf91c6"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$i1 = "RGSESSIONID="
		$s2 = "upload$"
		$s3 = "download$"
		$s4 = "cmd$"
		$s5 = "cmd.exe"

	condition:
		ESET_IIS_Native_Module_PRIVATE and ($i1 or all of ($s*))
}
