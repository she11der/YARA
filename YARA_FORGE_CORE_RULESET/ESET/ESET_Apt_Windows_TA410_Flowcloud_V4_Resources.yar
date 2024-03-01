import "pe"

rule ESET_Apt_Windows_TA410_Flowcloud_V4_Resources : FILE
{
	meta:
		description = "Matches sequence of PE resource IDs found in TA410 FlowCloud version 4.1.3"
		author = "ESET Research"
		id = "57b98823-439f-5a2c-a8cb-ac5e98953b06"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L722-L741"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "7b475cfddb5f995f7e8e3293b8e6ae59a9e36143998bc444499b5dce467f8e9d"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint16(0)==0x5a4d and pe.number_of_resources>=6 and for 5resource in pe.resources : (resource.type==10 and resource.language==1033 and (resource.name_string=="1\x000\x000\x000\x000\x00" or resource.name_string=="1\x000\x000\x000\x001\x00" or resource.name_string=="1\x000\x000\x000\x002\x00" or resource.name_string=="1\x000\x000\x000\x003\x00" or resource.name_string=="1\x000\x000\x000\x004\x00" or resource.name_string=="1\x000\x000\x000\x005\x00" or resource.name_string=="1\x000\x001\x000\x000\x00"))
}
