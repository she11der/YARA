import "pe"

rule ESET_Apt_Windows_TA410_Flowcloud_Pdb : FILE
{
	meta:
		description = "Matches PDB paths found in TA410 FlowCloud."
		author = "ESET Research"
		id = "8bf25768-941e-55c6-bd21-f6b614c9d75d"
		date = "2021-10-12"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/ta410/ta410.yar#L554-L567"
		license_url = "https://github.com/eset/malware-ioc/blob/089121b074e13feca43c9c6898cc901a3d637e42/LICENSE"
		logic_hash = "ff95ab0f8e68efe612a6e0d70cebd8bf815d6b5e3877c098ac0761382dc310d6"
		score = 75
		quality = 80
		tags = "FILE"
		license = "BSD 2-Clause"
		version = "1"

	condition:
		uint16(0)==0x5a4d and (pe.pdb_path contains "\\FlowCloud\\trunk\\" or pe.pdb_path contains "\\flowcloud\\trunk\\")
}
