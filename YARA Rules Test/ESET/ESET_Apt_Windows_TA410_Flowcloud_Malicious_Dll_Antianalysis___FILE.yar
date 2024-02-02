rule ESET_Apt_Windows_TA410_Flowcloud_Malicious_Dll_Antianalysis___FILE
{
	meta:
		description = "Matches anti-analysis techniques used in TA410 FlowCloud hijacking DLL."
		author = "ESET Research"
		id = "b38a1d4d-5053-5a6d-be8c-c00261936417"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L519-L552"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "8f14352118d32a43c17f70bd753acc48bd314965f10ab97818e8a434bbda96d9"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$chunk_1 = {
            33 C0
            E8 ?? ?? ?? ??
            83 C0 10
            3D 00 00 00 80
            7D 01
            EB FF
            E0 50
            C3
}