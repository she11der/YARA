import "pe"

rule ESET_IIS_Group02
{
	meta:
		description = "Detects Group 2 native IIS malware family"
		author = "ESET Research"
		id = "945e3748-1072-55f3-abaa-903dfc250294"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/badiis/badiis.yar#L134-L155"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "3fa2b8fed3c580f446b55412a920a5cfed2317b06aa93d059e9f89fdbec8f683"
		score = 75
		quality = 76
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "HttpModule.pdb" ascii wide
		$s2 = "([\\w+%]+)=([^&]*)"
		$s3 = "([\\w+%]+)=([^!]*)"
		$s4 = "cmd.exe"
		$s5 = "C:\\Users\\Iso\\Documents\\Visual Studio 2013\\Projects\\IIS 5\\x64\\Release\\Vi.pdb" ascii wide
		$s6 = "AVRSAFunction"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 3 of ($s*)
}
