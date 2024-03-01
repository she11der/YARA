rule SIGNATURE_BASE_SUSP_Size_Of_ASUS_Tuningtool : FILE
{
	meta:
		description = "Detects an ASUS tuning tool with a suspicious size"
		author = "Florian Roth (Nextron Systems)"
		id = "d22a1bf9-55d6-5cb4-9537-ad13b23af4d1"
		date = "2018-10-17"
		modified = "2022-12-21"
		reference = "https://www.welivesecurity.com/2018/10/17/greyenergy-updated-arsenal-dangerous-threat-actors/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/generic_anomalies.yar#L392-L407"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "5aadb48f61947ff0362bde5f80830b835ca9e3cb7e1c632d153d0ea5f8bbad6c"
		score = 60
		quality = 85
		tags = "FILE"
		noarchivescan = 1
		hash1 = "d4e97a18be820a1a3af639c9bca21c5f85a3f49a37275b37fd012faeffcb7c4a"

	strings:
		$s1 = "\\Release\\ASGT.pdb" ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and filesize >70KB and all of them
}
