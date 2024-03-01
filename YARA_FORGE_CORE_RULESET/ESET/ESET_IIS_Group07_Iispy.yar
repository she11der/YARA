import "pe"

rule ESET_IIS_Group07_Iispy
{
	meta:
		description = "Detects Group 7 native IIS malware family (IISpy)"
		author = "ESET Research"
		id = "64ed0189-a0be-5592-b9c6-1622700a7ed7"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/badiis/badiis.yar#L261-L296"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "ec5db5f36d06f9b0bdfe598fc72431da35afc1473dcc29f437a0f48ea9835a03"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "/credential/username"
		$s2 = "/credential/password"
		$s3 = "/computer/domain"
		$s4 = "/computer/name"
		$s5 = "/password"
		$s6 = "/cmd"
		$s7 = "%.8s%.8s=%.8s%.16s%.8s%.16s"
		$s8 = "ImpersonateLoggedOnUser"
		$s9 = "WNetAddConnection2W"
		$t1 = "X-Forwarded-Proto"
		$t2 = "Sec-Fetch-Mode"
		$t3 = "Sec-Fetch-Site"
		$t4 = "Cookie"
		$t5 = {49 45 4E 44 AE 42 60 82}
		$t6 = {89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44 52}

	condition:
		ESET_IIS_Native_Module_PRIVATE and 2 of ($s*) and any of ($t*)
}
