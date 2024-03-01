import "pe"

rule ESET_IIS_Group13_Iiserpent
{
	meta:
		description = "Detects Group 13 native IIS malware family (IISerpent)"
		author = "ESET Research"
		id = "f22dffb1-466f-5a7b-b9aa-de7ba991db1a"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/badiis/badiis.yar#L497-L523"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "7077b842c53ee1581ad4150cdfaac3502bfc0fbd3b823190ad648e09f36e442d"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "/mconfig/lunlian.txt"
		$s2 = "http://sb.qrfy.ne"
		$s3 = "folderlinkpath"
		$s4 = "folderlinkcount"
		$s5 = "onlymobilespider"
		$s6 = "redirectreferer"
		$s7 = "loadSuccessfull : "
		$s8 = "spider"
		$s9 = "<a href="
		$s11 = "?ReloadModuleConfig=1"
		$s12 = "?DisplayModuleConfig=1"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 5 of them
}
