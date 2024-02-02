rule ESET_Apt_Windows_TA410_Lookback_Decryption___FILE
{
	meta:
		description = "Matches encryption/decryption function used by LookBack."
		author = "ESET Research"
		id = "91947c6b-f357-5cf8-8522-4dcd517d01cb"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L189-L254"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "016dca6be654fcd193acc481e6a998efbb77e7ebd09b26614422be1136dd02c0"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$initialize = {
            8B C6           //mov eax, esi
            99              //cdq
            83 E2 03        //and edx, 3
            03 C2           //add eax, edx
            C1 F8 02        //sar eax, 2
            8A C8           //mov cl, al
            02 C0           //add al, al
            02 C8           //add cl, al
            88 4C 34 10         //mov byte ptr [esp + esi + 0x10], cl
            46              //inc esi
            81 FE 00 01 00 00       //cmp esi, 0x100
            72 ??
}